# Stage, commit and push all changes to the current branch.
# Usage: .\git-auto.ps1             (prompts for a commit message)
#        .\git-auto.ps1 "message"   (uses the message given)
param([string]$Message)

# 1. Stage all changes (.gitignore keeps .venv, __pycache__ and raw JSON out)
git add .

# 2. Stop if there is nothing to commit
git diff --cached --quiet
if ($LASTEXITCODE -eq 0) {
    Write-Host "Nothing to commit."
    exit
}

# 3. Show what will be committed
$changes = @(git status --short)
Write-Host "$($changes.Count) file(s) to be committed. First 20:"
$changes | Select-Object -First 20

# 4. Get the commit message
if ([string]::IsNullOrWhiteSpace($Message)) {
    $Message = Read-Host "Enter your commit message"
}
if ([string]::IsNullOrWhiteSpace($Message)) {
    Write-Host "Commit cancelled."
    exit
}

# 5. Commit
git commit -q -m $Message
if ($LASTEXITCODE -ne 0) {
    Write-Host "Commit failed. Not pushing."
    exit 1
}

# 6. Push to the current branch
$branch = git rev-parse --abbrev-ref HEAD
Write-Host "Pushing to origin/$branch..."
git push origin $branch
if ($LASTEXITCODE -ne 0) {
    Write-Host "Push failed. Your commit is saved locally."
    exit 1
}

Write-Host "Done! Your changes have been pushed."