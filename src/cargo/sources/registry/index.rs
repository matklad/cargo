use std::collections::HashMap;
use std::path::Path;
use std::str;
use std::borrow::Cow;

use serde_json;
use semver::Version;
use bincode;

use core::dependency::{Dependency, Kind};
use core::{PackageId, SourceId, Summary};
use sources::registry::{RegistryPackage, INDEX_LOCK};
use sources::registry::RegistryData;
use util::{internal, CargoResult, Config, Filesystem};
use sources::registry::RegistryDependency;
use util::paths;
use util::profile;

pub struct RegistryIndex<'cfg> {
    source_id: SourceId,
    path: Filesystem,
    cache: HashMap<String, Vec<(Summary, bool)>>,
    hashes: HashMap<String, HashMap<Version, String>>,
    // (name, vers) => cksum
    config: &'cfg Config,
    locked: bool,
}

fn loc() -> &'static Path {
    Path::new("/tmp/foo.bincode")
}

impl<'cfg> Drop for RegistryIndex<'cfg> {
    fn drop(&mut self) {
        let _p = profile::start("saving registry");

        let cache: HashMap<&str, Vec<RegistryPackage>> = self.cache.iter().map(|(k, summs)| {
            let pkgs = summs.iter().map(|&(ref s, yanked)| RegistryPackage {
                name: Cow::from(s.name().as_str()),
                vers: s.version().clone(),
                deps: s.dependencies().iter().map(|dep| {
                    RegistryDependency {
                        name: Cow::from(dep.name().as_str()),
                        req: Cow::from(dep.version_req().clone().to_string()),
                        features: dep.features().iter().map(|f| f.as_str().to_string()).collect(),
                        optional: dep.is_optional(),
                        default_features: dep.uses_default_features(),
                        target: dep.platform().map(|p| Cow::from(p.to_string())),
                        kind: match dep.kind() {
                            Kind::Normal => None,
                            Kind::Development => Some(Cow::from("dev")),
                            Kind::Build => Some(Cow::from("build")),
                        },
                        registry: if dep.source_id().is_registry() {
                            Some(dep.source_id().url().to_string())
                        } else {
                            None
                        },
                    }
                }).collect(),
                features: s.features().iter()
                    .map(|(k, v)| (k.clone(), v.iter().map(|f| f.to_string()).collect()))
                    .collect(),
                cksum: s.checksum().unwrap().to_string(),
                yanked: if yanked { Some(true) } else { None },
                links: s.links().map(|s| s.as_str().to_string()),
            });
            (k.as_str(), pkgs.collect())
        }).collect();
        let data = (cache, &self.hashes);
        let data = bincode::serialize(&data).unwrap();
        let loc = loc();

        paths::write(loc, &data).unwrap();
    }
}

impl<'cfg> RegistryIndex<'cfg> {
    pub fn new(
        id: &SourceId,
        path: &Filesystem,
        config: &'cfg Config,
        locked: bool,
    ) -> RegistryIndex<'cfg> {
        let loc = loc();
        let (cache, hashes) = if loc.exists() {
            let _p = profile::start("loading registry");
            let data = paths::read_bytes(loc).unwrap();
            let (cache, hashes): (HashMap<String, Vec<RegistryPackage>>, _)
            = bincode::deserialize(&data).unwrap();

            let cache = cache.into_iter().map(|(k, sums)| {
                (k, sums.into_iter().map(|RegistryPackage {
                                               name,
                                               vers,
                                               cksum,
                                               deps,
                                               features,
                                               yanked,
                                               links,
                                           }| {
                    let pkgid = PackageId::new(&name, &vers, &id).unwrap();
                    let deps = deps.into_iter().map(|dep| dep.into_dep(&id).unwrap())
                        .collect::<Vec<_>>();
                    let summary = Summary::new(pkgid, deps, features, links).unwrap();
                    let summary = summary.set_checksum(cksum.clone());
                    (summary, yanked.unwrap_or(false))
                }).collect())
            }).collect();

            (cache, hashes)
        } else {
            Default::default()
        };

        RegistryIndex {
            source_id: id.clone(),
            path: path.clone(),
            cache,
            hashes,
            config,
            locked,
        }
    }

    /// Return the hash listed for a specified PackageId.
    pub fn hash(&mut self, pkg: &PackageId, load: &mut RegistryData) -> CargoResult<String> {
        let name = &*pkg.name();
        let version = pkg.version();
        if let Some(s) = self.hashes.get(name).and_then(|v| v.get(version)) {
            return Ok(s.clone());
        }
        // Ok, we're missing the key, so parse the index file to load it.
        self.summaries(name, load)?;
        self.hashes
            .get(name)
            .and_then(|v| v.get(version))
            .ok_or_else(|| internal(format!("no hash listed for {}", pkg)))
            .map(|s| s.clone())
    }

    /// Parse the on-disk metadata for the package provided
    ///
    /// Returns a list of pairs of (summary, yanked) for the package name
    /// specified.
    pub fn summaries(
        &mut self,
        name: &str,
        load: &mut RegistryData,
    ) -> CargoResult<&Vec<(Summary, bool)>> {
        if self.cache.contains_key(name) {
            return Ok(&self.cache[name]);
        }
        let summaries = self.load_summaries(name, load)?;
        self.cache.insert(name.to_string(), summaries);
        Ok(&self.cache[name])
    }

    fn load_summaries(
        &mut self,
        name: &str,
        load: &mut RegistryData,
    ) -> CargoResult<Vec<(Summary, bool)>> {
        let (root, _lock) = if self.locked {
            let lock = self.path
                .open_ro(Path::new(INDEX_LOCK), self.config, "the registry index");
            match lock {
                Ok(lock) => (lock.path().parent().unwrap().to_path_buf(), Some(lock)),
                Err(_) => return Ok(Vec::new()),
            }
        } else {
            (self.path.clone().into_path_unlocked(), None)
        };

        let fs_name = name.chars()
            .flat_map(|c| c.to_lowercase())
            .collect::<String>();

        // see module comment for why this is structured the way it is
        let path = match fs_name.len() {
            1 => format!("1/{}", fs_name),
            2 => format!("2/{}", fs_name),
            3 => format!("3/{}/{}", &fs_name[..1], fs_name),
            _ => format!("{}/{}/{}", &fs_name[0..2], &fs_name[2..4], fs_name),
        };
        let mut ret = Vec::new();
        let mut hit_closure = false;
        let err = load.load(&root, Path::new(&path), &mut |contents| {
            hit_closure = true;
            let contents = str::from_utf8(contents)
                .map_err(|_| format_err!("registry index file was not valid utf-8"))?;
            ret.reserve(contents.lines().count());
            let lines = contents.lines().map(|s| s.trim()).filter(|l| !l.is_empty());

            let online = !self.config.cli_unstable().offline;
            // Attempt forwards-compatibility on the index by ignoring
            // everything that we ourselves don't understand, that should
            // allow future cargo implementations to break the
            // interpretation of each line here and older cargo will simply
            // ignore the new lines.
            ret.extend(lines.filter_map(|line| {
                self.parse_registry_package(line).ok().and_then(|v| {
                    if online || load.is_crate_downloaded(v.0.package_id()) {
                        Some(v)
                    } else {
                        None
                    }
                })
            }));

            Ok(())
        });

        // We ignore lookup failures as those are just crates which don't exist
        // or we haven't updated the registry yet. If we actually ran the
        // closure though then we care about those errors.
        if hit_closure {
            err?;
        }

        Ok(ret)
    }

    /// Parse a line from the registry's index file into a Summary for a
    /// package.
    ///
    /// The returned boolean is whether or not the summary has been yanked.
    fn parse_registry_package(&mut self, line: &str) -> CargoResult<(Summary, bool)> {
        let RegistryPackage {
            name,
            vers,
            cksum,
            deps,
            features,
            yanked,
            links,
        } = serde_json::from_str(line)?;
        let pkgid = PackageId::new(&name, &vers, &self.source_id)?;
        let deps = deps.into_iter().map(|dep| dep.into_dep(&self.source_id))
            .collect::<CargoResult<Vec<_>>>()?;
        let summary = Summary::new(pkgid, deps, features, links)?;
        let summary = summary.set_checksum(cksum.clone());
        if self.hashes.contains_key(&name[..]) {
            self.hashes.get_mut(&name[..]).unwrap().insert(vers, cksum);
        } else {
            self.hashes
                .entry(name.into_owned())
                .or_insert_with(HashMap::new)
                .insert(vers, cksum);
        }
        Ok((summary, yanked.unwrap_or(false)))
    }

    pub fn query(
        &mut self,
        dep: &Dependency,
        load: &mut RegistryData,
        f: &mut FnMut(Summary),
    ) -> CargoResult<()> {
        let source_id = self.source_id.clone();
        let summaries = self.summaries(&*dep.name(), load)?;
        let summaries = summaries
            .iter()
            .filter(|&&(_, yanked)| dep.source_id().precise().is_some() || !yanked)
            .map(|s| s.0.clone());

        // Handle `cargo update --precise` here. If specified, our own source
        // will have a precise version listed of the form
        // `<pkg>=<p_req>o-><f_req>` where `<pkg>` is the name of a crate on
        // this source, `<p_req>` is the version installed and `<f_req> is the
        // version requested (argument to `--precise`).
        let summaries = summaries.filter(|s| match source_id.precise() {
            Some(p) if p.starts_with(&*dep.name()) && p[dep.name().len()..].starts_with('=') => {
                let mut vers = p[dep.name().len() + 1..].splitn(2, "->");
                if dep.version_req()
                    .matches(&Version::parse(vers.next().unwrap()).unwrap())
                    {
                        vers.next().unwrap() == s.version().to_string()
                    } else {
                    true
                }
            }
            _ => true,
        });

        for summary in summaries {
            if dep.matches(&summary) {
                f(summary);
            }
        }
        Ok(())
    }
}
