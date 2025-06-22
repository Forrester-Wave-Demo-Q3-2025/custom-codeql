# custom-codeql

## Packs / Queries

- `forrester-wave-demo-q3-2025/codeql-custom-java` pack (`language: java`)
  - [java/WaveSqlTainted.ql](https://github.com/Forrester-Wave-Demo-Q3-2025/custom-codeql/blob/main/java/WaveSqlTainted.ql)

## Usage

```yml
    # Initializes the CodeQL tools for scanning.
    - name: Initialize CodeQL
      uses: github/codeql-action/init@v3
      with:
        languages: ${{ matrix.language }}
        build-mode: ${{ matrix.build-mode }}
        config: | 
          threat-models: local

          queries:
            - name: Expands analysis to use the built-in security-extended suite
              uses: security-extended
            # - name: Use an external query (run a single query from an external CodeQL repo without pre-compilation)
            #   uses: Forrester-Wave-Demo-Q3-2025/custom-codeql/java/WaveSqlTainted.ql@main              
          packs:
            # For Java and Kotlin analysis
            #  - Use an external package:query (precompiled and hosted on the GitHub package registy)
            java:          
              - forrester-wave-demo-q3-2025/codeql-custom-java:WaveSqlTainted.ql


```

## Pack Creation

Increment the pack version in .java/qlpack.yml

```cmd
unset GITHUB_TOKEN
gh auth login --scopes "write:packages,read:packages,repo"

gh extensions install github/gh-codeql
gh codeql --version


gh codeql pack install ./java
gh codeql pack create ./java

gh auth token | gh codeql pack publish ./java --github-auth-stdin

gh api "/orgs/Forrester-Wave-Demo-Q3-2025/packages/container/codeql-custom-java"

```
