# PhishTrap Real-Time Security Analyzer

Advanced real-time website security analysis and threat detection system with desktop application support.

## Features

### 🛡️ Real-Time Security Analysis
- **XSS Detection** - Cross-Site Scripting vulnerability detection
- **SQL Injection Detection** - Database attack pattern identification
- **Phishing Detection** - Malicious website identification
- **SSL/TLS Analysis** - Certificate and encryption validation
- **Security Headers Analysis** - HTTP security header verification
- **Real-Time Threat Monitoring** - Live threat detection and blocking

### 🖥️ Desktop Application
- **Native Desktop App** - Runs as standalone executable (.exe)
- **Menu Integration** - Full application menu with keyboard shortcuts
- **File Operations** - Export results, save reports
- **System Integration** - Native dialogs and notifications
- **Cross-Platform** - Windows, macOS, and Linux support

### 📊 Advanced Analytics
- **Comprehensive Statistics** - Detailed security metrics
- **Threat Visualization** - Interactive charts and graphs
- **Historical Analysis** - Scan history and trends
- **Real-Time Monitoring** - Live system status and activity

## Installation

### Web Version
1. Clone the repository
2. Install dependencies: `npm install`
3. Start development server: `npm run dev`
4. Open http://localhost:5173

### Desktop Application

#### Development
```bash
# Install dependencies
npm install

# Run in development mode
npm run electron-dev
```

#### Build Executable

##### Windows (.exe)
```bash
# Build Windows executable
npm run build-exe
```

##### All Platforms
```bash
# Build for Windows, macOS, and Linux
npm run build-all
```

#### Build Output
- **Windows**: `dist-electron/PhishTrap Security Analyzer Setup.exe`
- **Portable**: `dist-electron/PhishTrap Security Analyzer.exe`
- **macOS**: `dist-electron/PhishTrap Security Analyzer.dmg`
- **Linux**: `dist-electron/PhishTrap Security Analyzer.AppImage`

## Usage

### Desktop Application
1. **Launch** the application from your desktop or start menu
2. **Activate** the security system using the power button
3. **Enter URL** to analyze in the input field
4. **Review Results** in the comprehensive analysis tabs
5. **Export Results** using File → Export Results or Ctrl+E

### Keyboard Shortcuts
- `Ctrl+N` - New Analysis
- `Ctrl+A` - Toggle Security System
- `Ctrl+1-4` - Switch between tabs
- `Ctrl+E` - Export Results
- `Ctrl+R` - Reload Application
- `F11` - Toggle Fullscreen
- `Ctrl+Q` - Exit Application

### Menu Options
- **File Menu** - New analysis, export results, exit
- **Security Menu** - System controls, protection levels
- **View Menu** - Tab navigation, zoom controls
- **Help Menu** - About, shortcuts, documentation

## Security Features

### Real-Time Detection
- **Pattern Analysis** - Advanced malicious pattern recognition
- **Behavioral Analysis** - Suspicious activity detection
- **Content Scanning** - Deep page content analysis
- **Network Monitoring** - Request and response analysis

### Vulnerability Assessment
- **XSS Vectors** - Script injection detection
- **SQL Injection** - Database attack identification
- **CSRF Protection** - Cross-site request forgery detection
- **Clickjacking** - UI redressing attack prevention

### System Protection
- **Active/Inactive Control** - System-wide protection toggle
- **Protection Levels** - Basic, Enhanced, Maximum security
- **Real-Time Blocking** - Automatic threat mitigation
- **Evidence Collection** - Detailed attack documentation

## Technical Details

### Architecture
- **Frontend**: React + TypeScript + Tailwind CSS
- **Desktop**: Electron with secure preload scripts
- **Build System**: Vite + Electron Builder
- **Security**: Context isolation, no node integration

### File Structure
```
src/
├── components/          # React components
├── hooks/              # Custom hooks (including Electron integration)
├── types/              # TypeScript type definitions
├── utils/              # Security analysis utilities
└── App.tsx            # Main application component

public/
├── electron.js         # Main Electron process
├── preload.js         # Secure preload script
└── favicon.ico        # Application icon

dist-electron/          # Built desktop applications
```

### Security Considerations
- **Context Isolation** - Secure communication between processes
- **No Node Integration** - Renderer process security
- **CSP Headers** - Content Security Policy implementation
- **Secure Defaults** - Minimal privilege principle

## Development

### Prerequisites
- Node.js 18+ 
- npm or yarn
- Git

### Setup
```bash
# Clone repository
git clone <repository-url>
cd phishtrap

# Install dependencies
npm install

# Start development
npm run electron-dev
```

### Building
```bash
# Build web version
npm run build

# Build desktop application
npm run build-exe

# Build all platforms
npm run build-all
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

- **Issues**: Report bugs and request features
- **Documentation**: Comprehensive user guides
- **Community**: Join our security community

## Disclaimer

This tool is for educational and security research purposes. Always ensure you have permission before analyzing websites. The developers are not responsible for misuse of this software.