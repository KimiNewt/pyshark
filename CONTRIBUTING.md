# Contributing to Pyshark

Thank you for your interest in contributing to Pyshark! Your efforts help us maintain and improve this project for the community of network packet analysis enthusiasts.

Below, you'll find guidelines for contributing, reporting issues, and submitting pull requests. Following these steps ensures that your contributions are effectively integrated into the project.

## How Can I Contribute?

### Reporting Bugs

- Check the issues page to ensure the bug hasn’t already been reported.
- Include a clear and descriptive title for the issue.
- Provide steps to reproduce the issue, expected results, and the actual behavior.
- Include relevant logs, error message, and environmental details (e.g., Python version, OS).

### Suggesting Enhancements

- Open a new issue for your enhancement idea and label it as a "Feature Request."
- Describe your proposal clearly, including:
  - The problem it solves.
  - How it improves the project.
  - Any alternative solutions you've considered.

### Adding New Features

- Propose your feature in the issues page for discussion.
- Ensure your code adheres to the repository's coding standards.
– Write appropriate tests and documentation for your feature.

### Submitting a Pull Request (PR)

- Fork the repository and clone your fork locally.
- Create a branch for your work:

```
git checkout -b feature/your-feature-name
```

Make your changes, ensuring you:

- Follow the coding style used in the repository.
- Include tests for new features or bug fixes.
- Update the documentation (e.g., README.md) as needed.

Commit your changes with a meaningful message:

```
git commit -m "Add feature: [short description of your change]"
```

Push your branch to GitHub:

```
git push origin feature/your-feature-name
```

- Open a Pull Request from your branch to the main branch of this repository.
- Fill in the PR template and provide:
  - A description of the changes.
  - The problem it addresses.
  - Links to any related issues.

## Guidelines for Code Contributions

### Coding Standards

- Use PEP 8 for Python code styling. Run tools like flake8 or black to ensure consistency.
- Write descriptive comments for complex sections of code.

### Testing

- Include tests in the tests/ directory.
- Use pytest for writing test cases.
- Ensure that all tests pass by running:

```
pytest
```

### Documentation

If your change affects the functionality or API, update the relevant documentation in README.md or other relevant files.

### Getting Help

If you have questions or need assistance, feel free to open a discussion or email the maintainers.
