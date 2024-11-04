#!/bin/bash

function ignore(){
  git update-index --assume-unchanged bpf/include/bpf_helper_defs_ext.h 
  git update-index --assume-unchanged config/kmesh_marcos_def.h 
  git update-index --assume-unchanged bpf/kmesh/bpf2go/bpf2go.go
  git update-index --assume-unchanged mk/api-v2-c.pc 
  git update-index --assume-unchanged mk/bpf.pc
}

ignore

if [[ -n $(git status --porcelain) ]]; then
  git status
  git diff
  echo "ERROR: Some files need to be updated, please run 'make gen' and include any changed files in your PR"
  exit 1
fi
