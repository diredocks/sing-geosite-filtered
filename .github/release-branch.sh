#!/bin/bash

set -e -o pipefail

mkdir -p release
cd release
git init
git config --local user.email "github-action@users.noreply.github.com"
git config --local user.name "GitHub Action"
git remote add origin https://x-access-token:$GITHUB_TOKEN@github.com/$GITHUB_REPOSITORY.git
git branch -M release
cp -r ../rule-set-filtered .
git add .
git commit -m "Update release"
git push -f origin release
