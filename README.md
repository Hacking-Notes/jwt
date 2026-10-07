<a name="top"></a>

<div align="center">

<img src="assets/header.svg" alt="JWT" width="100%" />

<br />

<a href="https://github.com/Hacking-Notes/jwt/stargazers"><img src="https://img.shields.io/github/stars/Hacking-Notes/jwt?style=for-the-badge&logo=github&logoColor=1f2328&label=Stars&labelColor=f6f8fa&color=059669" alt="Stars" /></a>
<a href="https://github.com/Hacking-Notes/jwt/network/members"><img src="https://img.shields.io/github/forks/Hacking-Notes/jwt?style=for-the-badge&logo=git&logoColor=1f2328&label=Forks&labelColor=f6f8fa&color=0284c7" alt="Forks" /></a>
<a href="https://github.com/Hacking-Notes/jwt/commits"><img src="https://img.shields.io/github/last-commit/Hacking-Notes/jwt?style=for-the-badge&label=Updated&labelColor=f6f8fa&color=7c3aed" alt="Last commit" /></a>
<a href="LICENSE"><img src="https://img.shields.io/github/license/Hacking-Notes/jwt?style=for-the-badge&label=License&labelColor=f6f8fa&color=0284c7" alt="License" /></a>
<a href="https://hacking-notes.com"><img src="https://img.shields.io/badge/More-hacking--notes.com-db2777?style=for-the-badge&labelColor=f6f8fa" alt="hacking-notes.com" /></a>

</div>

<br />

A powerful Chrome extension for security testing and manipulating JWT (JSON Web Tokens) in web applications. This tool enables security professionals and developers to test different attack vectors by modifying JWT tokens on the fly during security assessments and penetration testing.

![image](https://github.com/user-attachments/assets/2c7d8638-20e7-4671-90a3-823d0a32fa9b)

## Features

- Real-time JWT token manipulation and testing
- On-the-fly token payload modification
- Common JWT attack vector testing
- Token signature validation bypass testing
- Token expiration manipulation
- Algorithm switching capabilities
- DevTools integration for advanced token analysis
- Cookie and localStorage token interception
- Clipboard support for easy token manipulation


<img src="assets/divider.svg" width="100%" alt="" />

## Security Testing Capabilities

- Test privilege escalation by modifying user roles and permissions
- Manipulate token claims to test authorization boundaries
- Bypass signature verification
- Test token expiration handling
- Modify algorithm headers (e.g., 'none' algorithm attacks)
- Inject custom claims for security testing
- Test token replay protection mechanisms


<img src="assets/divider.svg" width="100%" alt="" />

## Installation

1. Clone this repository or download the source code
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" and select the extension directory


<img src="assets/divider.svg" width="100%" alt="" />

## Usage

1. Click the extension icon in your Chrome toolbar to access the popup interface
2. Open Chrome DevTools and find the JWT panel for advanced features
3. The extension will automatically detect and parse JWT tokens in Cookies


<img src="assets/divider.svg" width="100%" alt="" />

## Project Structure

```
├── manifest.json        # Extension configuration
├── devtools.html        # DevTools panel entry
├── panel.html           # Main DevTools panel UI
├── images/              # Extension icons
├── css/                 # Stylesheets
└── js/                  # JavaScript files
```


<img src="assets/divider.svg" width="100%" alt="" />

## Development

To modify or enhance the extension:
1. Make your changes to the source code
2. Reload the extension in `chrome://extensions/`
3. Test your changes


<img src="assets/divider.svg" width="100%" alt="" />

## Security Note

This extension is designed for development and testing purposes only. Be cautious when using it with sensitive JWT tokens in production environments.


<img src="assets/divider.svg" width="100%" alt="" />

## License

This project is open source and available under the MIT License.


<img src="assets/divider.svg" width="100%" alt="" />

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

<img src="assets/divider.svg" width="100%" alt="" />

## 🧰 Hacking Notes Ecosystem

<div align="center">

🌐 &nbsp;**[hacking-notes.com](https://hacking-notes.com)** &nbsp;·&nbsp; ✍️ &nbsp;**[blog](https://hacking-notes.medium.com/)** &nbsp;·&nbsp; 💬 &nbsp;**[discord](https://discord.gg/r68ameNHrD)**

</div>

| | Resource | What you get |
| :-: | -------- | ------------ |
| 🗺 | **[Hacker-Roadmap](https://github.com/Hacking-Notes/Hacker-Roadmap)** | Structured paths from beginner to pro — hobbyist, bug bounty, certs & degree. |
| 🔴 | **[RedTeam Notes](https://github.com/Hacking-Notes/RedTeam)** | Offensive security notes: recon, exploitation, Windows & Linux. |
| 🔷 | **[BlueTeam Notes](https://github.com/Hacking-Notes/BlueTeam)** | Defensive security notes: forensics, malware, log & packet analysis. |
| 🧩 | **[Extensions](https://github.com/Hacking-Notes/Extensions)** | Curated Chrome extensions for ethical hacking & recon. |
| 🔖 | **[Bookmarks](https://github.com/Hacking-Notes/Bookmarks)** | Curated hacker bookmark collection, one import away. |

<img src="assets/footer.svg" width="100%" alt="" />

<div align="right"><a href="#top">⬆ back to top</a></div>
