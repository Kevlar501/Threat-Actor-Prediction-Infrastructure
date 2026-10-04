# 1. Stage all changes
git add .

# 2. Ask the user for the commit message
$commit_msg = Read-Host "Enter your commit message"

# 3. Check if the user cancelled
if ([string]::IsNullOrEmpty($commit_msg)) {
    Write-Host "Commit cancelled."
    exit
}

# 4. Commit the changes
git commit -m $commit_msg

# 5. Push to remote
Write-Host "Pushing to remote repository..."
git push origin main

Write-Host "Done! Your changes have been pushed."