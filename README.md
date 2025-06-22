# custom-codeql

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
            - name: Expands analysis to use the built-in extended suite
              uses: security-extended          
            - name: Use an external query (run a single query from an external CodeQL pack)
              uses: Forrester-Wave-Demo-Q3-2025/custom-codeql/java/WaveSqlTainted.ql@main
```

## Pack Creation

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