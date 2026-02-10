use std::collections::{HashMap, HashSet};
use crate::errors::SekuraError;
use super::loader::TechniqueDefinition;

/// Topological sort of techniques based on depends_on fields.
/// Returns ordered list where dependencies come first.
pub fn topological_sort<'a>(
    techniques: &'a [TechniqueDefinition],
) -> Result<Vec<&'a TechniqueDefinition>, SekuraError> {
    // Build name -> index mapping
    let name_to_idx: HashMap<&str, usize> = techniques.iter()
        .enumerate()
        .map(|(i, t)| (t.name.as_str(), i))
        .collect();

    // Build adjacency list
    let mut deps: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, tech) in techniques.iter().enumerate() {
        if let Some(dep_name) = &tech.depends_on {
            if let Some(&dep_idx) = name_to_idx.get(dep_name.as_str()) {
                deps.entry(i).or_default().push(dep_idx);
            }
        }
    }

    // DFS-based topological sort
    let mut visited = HashSet::new();
    let mut in_stack = HashSet::new();
    let mut result = Vec::new();

    fn dfs<'a>(
        node: usize,
        deps: &HashMap<usize, Vec<usize>>,
        visited: &mut HashSet<usize>,
        in_stack: &mut HashSet<usize>,
        result: &mut Vec<usize>,
        techniques: &'a [TechniqueDefinition],
    ) -> Result<(), SekuraError> {
        if in_stack.contains(&node) {
            return Err(SekuraError::Config(format!(
                "Circular dependency detected involving technique: {}",
                techniques[node].name
            )));
        }
        if visited.contains(&node) {
            return Ok(());
        }

        in_stack.insert(node);
        if let Some(node_deps) = deps.get(&node) {
            for &dep in node_deps {
                dfs(dep, deps, visited, in_stack, result, techniques)?;
            }
        }
        in_stack.remove(&node);
        visited.insert(node);
        result.push(node);
        Ok(())
    }

    for i in 0..techniques.len() {
        if !visited.contains(&i) {
            dfs(i, &deps, &mut visited, &mut in_stack, &mut result, techniques)?;
        }
    }

    Ok(result.iter().map(|&i| &techniques[i]).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_technique(name: &str, depends_on: Option<&str>) -> TechniqueDefinition {
        TechniqueDefinition {
            name: name.to_string(),
            tool: "nmap".to_string(),
            command: "nmap {target}".to_string(),
            description: "test".to_string(),
            intensity: "standard".to_string(),
            timeout: 300,
            parse_hint: None,
            depends_on: depends_on.map(|s| s.to_string()),
            depends_on_ports: None,
        }
    }

    #[test]
    fn test_topological_sort_no_deps() {
        let techniques = vec![
            make_technique("a", None),
            make_technique("b", None),
            make_technique("c", None),
        ];
        let sorted = topological_sort(&techniques).unwrap();
        assert_eq!(sorted.len(), 3);
        let names: Vec<&str> = sorted.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_topological_sort_with_deps() {
        let techniques = vec![
            make_technique("b", Some("a")),
            make_technique("a", None),
        ];
        let sorted = topological_sort(&techniques).unwrap();
        let names: Vec<&str> = sorted.iter().map(|t| t.name.as_str()).collect();
        // "a" must come before "b"
        let a_pos = names.iter().position(|&n| n == "a").unwrap();
        let b_pos = names.iter().position(|&n| n == "b").unwrap();
        assert!(a_pos < b_pos);
    }

    #[test]
    fn test_topological_sort_missing_dep() {
        // "b" depends on "nonexistent" which is not in the list -- should still succeed
        let techniques = vec![
            make_technique("a", None),
            make_technique("b", Some("nonexistent")),
        ];
        let sorted = topological_sort(&techniques).unwrap();
        assert_eq!(sorted.len(), 2);
    }

    #[test]
    fn test_topological_sort_chain() {
        let techniques = vec![
            make_technique("c", Some("b")),
            make_technique("b", Some("a")),
            make_technique("a", None),
        ];
        let sorted = topological_sort(&techniques).unwrap();
        let names: Vec<&str> = sorted.iter().map(|t| t.name.as_str()).collect();
        let a_pos = names.iter().position(|&n| n == "a").unwrap();
        let b_pos = names.iter().position(|&n| n == "b").unwrap();
        let c_pos = names.iter().position(|&n| n == "c").unwrap();
        assert!(a_pos < b_pos);
        assert!(b_pos < c_pos);
    }
}
