// release.config.js
export default {
  branches: ["main"],
  plugins: [
    "@semantic-release/commit-analyzer", // analyzes commits for version bumps
    "@semantic-release/release-notes-generator", // generates changelog text
    "@semantic-release/changelog", // updates CHANGELOG.md
    "@semantic-release/npm", // bumps version in package.json
    "@semantic-release/git", // commits changelog + package.json changes
    "@semantic-release/github", // creates GitHub releases
  ],
};
