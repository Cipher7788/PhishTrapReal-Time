# Programming Languages and Technologies Used in PhishTrap

## 🚀 **Primary Programming Languages**

### **1. TypeScript (Main Language)**
```typescript
// Example from src/types/index.ts
export interface AnalysisResult {
  url: string;
  threatLevel: 'safe' | 'suspicious' | 'malicious' | 'critical';
  score: number;
  maxScore: number;
  checks: SecurityCheck[];
  timestamp: number;
  recommendations: string[];
  vulnerabilities: Vulnerability[];
  realTimeThreats: RealTimeThreat[];
}
```

**Why TypeScript?**
- **Type Safety** - Prevents runtime errors with compile-time checking
- **Enhanced IDE Support** - Better autocomplete, refactoring, and debugging
- **Scalability** - Easier to maintain large codebases
- **Modern JavaScript Features** - ES6+, async/await, destructuring
- **Interface Definitions** - Clear contracts between components

**Usage in Project:**
- All React components are written in TypeScript
- Type definitions for security analysis data structures
- API interfaces and function signatures
- Configuration and utility functions

### **2. JavaScript (Node.js/Electron)**
```javascript
// Example from public/electron.js
const { app, BrowserWindow, Menu, shell, ipcMain, dialog } = require('electron');
const path = require('path');
const isDev = require('electron-is-dev');

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });
}
```

**Why JavaScript for Electron?**
- **Native Node.js Integration** - Access to file system, OS APIs
- **Electron Framework** - Desktop application development
- **System Integration** - Menus, notifications, file dialogs
- **Process Communication** - IPC between main and renderer processes

**Usage in Project:**
- Electron main process (desktop app backend)
- Preload scripts for secure API exposure
- Build scripts and configuration
- Desktop application logic

### **3. JSX/TSX (React Components)**
```tsx
// Example from src/components/RealTimeURLInput.tsx
export const RealTimeURLInput: React.FC<RealTimeURLInputProps> = ({ 
  onAnalyze, 
  isLoading, 
  systemStatus,
  onToggleSystem
}) => {
  const [url, setUrl] = useState('');
  
  return (
    <div className="bg-white rounded-xl shadow-lg p-6">
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          className="w-full px-4 py-3 border rounded-lg"
        />
      </form>
    </div>
  );
};
```

**Why JSX/TSX?**
- **Component-Based Architecture** - Reusable UI components
- **Declarative Syntax** - Easier to understand and maintain
- **Virtual DOM** - Efficient rendering and updates
- **Type Safety** - TypeScript integration with React components

**Usage in Project:**
- All React components and UI elements
- Interactive forms and user interfaces
- Real-time data display components
- Navigation and layout components

## 🎨 **Styling and Design Languages**

### **4. CSS (via Tailwind CSS)**
```css
/* Tailwind utility classes used throughout the project */
.bg-gradient-to-r {
  background-image: linear-gradient(to right, var(--tw-gradient-stops));
}

.from-blue-600 {
  --tw-gradient-from: #2563eb;
}

.shadow-lg {
  box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
}
```

**Why Tailwind CSS?**
- **Utility-First Approach** - Rapid development with pre-built classes
- **Responsive Design** - Built-in responsive utilities
- **Consistent Design System** - Standardized spacing, colors, typography
- **Performance** - Only includes used styles in production

**Usage in Project:**
- All component styling and layout
- Responsive design implementation
- Color schemes and visual hierarchy
- Animations and transitions

### **5. PostCSS**
```javascript
// postcss.config.js
export default {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
```

**Why PostCSS?**
- **CSS Processing** - Transforms modern CSS for browser compatibility
- **Plugin Ecosystem** - Autoprefixer, Tailwind integration
- **Build Optimization** - Minification and purging unused styles

## 🔧 **Configuration Languages**

### **6. JSON (Configuration)**
```json
// package.json example
{
  "name": "phishtrap-security-analyzer",
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "electron-dev": "concurrently \"npm run dev\" \"wait-on http://localhost:5173 && electron .\"",
    "build-exe": "npm run build && electron-builder --win"
  },
  "build": {
    "appId": "com.phishtrap.security",
    "productName": "PhishTrap Security Analyzer"
  }
}
```

**Why JSON?**
- **Configuration Files** - Package.json, tsconfig.json, build configs
- **Data Exchange** - API responses, export/import functionality
- **Settings Storage** - Application preferences and state

**Usage in Project:**
- Package dependencies and scripts
- TypeScript compiler configuration
- Electron builder settings
- Data export/import format

### **7. YAML/Configuration Files**
```yaml
# Example build configuration structure
build:
  appId: com.phishtrap.security
  productName: PhishTrap Security Analyzer
  directories:
    output: dist-electron
  win:
    target: nsis
    icon: public/favicon.ico
```

## 🛠️ **Build Tools and Languages**

### **8. Vite Configuration (TypeScript)**
```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ['react', 'react-dom'],
          utils: ['lucide-react']
        }
      }
    }
  }
});
```

**Why Vite?**
- **Fast Development** - Hot module replacement
- **Modern Build Tool** - ES modules, tree shaking
- **Plugin Ecosystem** - React, TypeScript integration
- **Optimized Production Builds** - Code splitting, minification

### **9. ESLint Configuration**
```javascript
// eslint.config.js
import js from '@eslint/js';
import globals from 'globals';
import reactHooks from 'eslint-plugin-react-hooks';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ['**/*.{ts,tsx}'],
    plugins: {
      'react-hooks': reactHooks,
    }
  }
);
```

**Why ESLint?**
- **Code Quality** - Consistent coding standards
- **Error Prevention** - Catches potential bugs
- **Best Practices** - Enforces React and TypeScript best practices

## 🔒 **Security Implementation Languages**

### **10. Security Analysis Algorithms (TypeScript)**
```typescript
// Real security analysis implementation
export class RealTimeSecurityAnalyzer {
  private static readonly XSS_PATTERNS = [
    /<script[^>]*>.*?<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,
    /<iframe[^>]*>/gi
  ];

  private static readonly SQL_INJECTION_PATTERNS = [
    /(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)/gi,
    /(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/gi,
    /'\s*(OR|AND)\s*'[^']*'\s*=\s*'/gi
  ];

  public static async analyzeWebsite(url: string): Promise<AnalysisResult> {
    // Real analysis implementation
    const vulnerabilities = await this.detectVulnerabilities(url);
    const realTimeThreats = this.detectRealTimeThreats(url);
    // ... more analysis logic
  }
}
```

**Security Features:**
- **Pattern Matching** - Regular expressions for threat detection
- **Real-time Analysis** - Actual URL and content analysis
- **Vulnerability Assessment** - XSS, SQL injection, phishing detection
- **Threat Classification** - Severity levels and evidence collection

## 📱 **Frontend Framework Technologies**

### **11. React 18 Features**
```typescript
// Modern React hooks usage
import { useState, useEffect, useCallback } from 'react';

export const useElectron = () => {
  const [isElectron, setIsElectron] = useState(false);
  const [appVersion, setAppVersion] = useState<string>('');

  useEffect(() => {
    const checkElectron = async () => {
      if (window.electronAPI) {
        setIsElectron(true);
        const version = await window.electronAPI.getAppVersion();
        setAppVersion(version);
      }
    };
    checkElectron();
  }, []);

  return { isElectron, appVersion };
};
```

**React Features Used:**
- **Functional Components** - Modern React development
- **Hooks** - useState, useEffect, custom hooks
- **Context API** - State management
- **Component Composition** - Reusable component architecture

## 🔧 **Development Tools**

### **12. Package Management**
```bash
# npm commands used
npm install          # Install dependencies
npm run dev         # Development server
npm run build       # Production build
npm run electron-dev # Desktop development
npm run build-exe   # Build executable
```

**Tools Used:**
- **npm** - Package management and script running
- **Concurrently** - Run multiple commands simultaneously
- **Wait-on** - Wait for services to be available
- **Electron Builder** - Desktop app packaging

## 🌐 **Web Technologies**

### **13. HTML5 (Template)**
```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>PhishTrap - Real-Time Security Analyzer</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

**Web Standards:**
- **HTML5** - Semantic markup and modern features
- **ES Modules** - Modern JavaScript module system
- **Web APIs** - Clipboard, notifications, file system

## 📊 **Summary of Languages by Usage**

| Language/Technology | Primary Use | Percentage of Codebase |
|-------------------|-------------|----------------------|
| **TypeScript** | Main application logic, components | 70% |
| **JavaScript** | Electron main process, build scripts | 15% |
| **CSS (Tailwind)** | Styling and design | 10% |
| **JSON** | Configuration and data | 3% |
| **HTML** | Application template | 1% |
| **Markdown** | Documentation | 1% |

## 🎯 **Why These Technologies Were Chosen**

**Type Safety & Reliability**
- TypeScript provides compile-time error checking
- Prevents common JavaScript runtime errors
- Better IDE support and developer experience

**Modern Development**
- React 18 with hooks for component state management
- Vite for fast development and optimized builds
- Tailwind CSS for rapid UI development

**Cross-Platform Compatibility**
- Electron enables desktop application development
- Web technologies ensure broad compatibility
- Responsive design works on all screen sizes

**Security Focus**
- TypeScript interfaces ensure data integrity
- Secure Electron configuration with context isolation
- Real-time analysis algorithms for genuine threat detection

**Professional Quality**
- ESLint for code quality and consistency
- Modern build tools for optimized production builds
- Comprehensive error handling and user feedback

This technology stack provides a robust foundation for building a professional-grade cybersecurity application that works reliably across web and desktop platforms while maintaining high security standards and excellent user experience.