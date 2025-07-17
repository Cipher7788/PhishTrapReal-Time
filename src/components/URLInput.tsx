import React, { useState } from 'react';
import { Search, Clipboard, X } from 'lucide-react';

interface URLInputProps {
  onAnalyze: (url: string) => void;
  isLoading: boolean;
}

export const URLInput: React.FC<URLInputProps> = ({ onAnalyze, isLoading }) => {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) {
      setError('Please enter a URL to analyze');
      return;
    }
    setError('');
    onAnalyze(url.trim());
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setUrl(text);
      setError('');
    } catch (err) {
      setError('Unable to access clipboard');
    }
  };

  const clearInput = () => {
    setUrl('');
    setError('');
  };

  return (
    <div className="bg-white rounded-xl shadow-lg p-6 mb-8">
      <h2 className="text-xl font-semibold text-gray-800 mb-4">
        Enter URL to Analyze
      </h2>
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com or example.com"
            className={`w-full px-4 py-3 pr-20 border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              error ? 'border-red-500' : 'border-gray-300'
            }`}
            disabled={isLoading}
          />
          
          <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex space-x-1">
            {url && (
              <button
                type="button"
                onClick={clearInput}
                className="p-1 text-gray-400 hover:text-red-500 transition-colors"
                disabled={isLoading}
              >
                <X size={16} />
              </button>
            )}
            
            <button
              type="button"
              onClick={handlePaste}
              className="p-1 text-gray-400 hover:text-blue-500 transition-colors"
              disabled={isLoading}
              title="Paste from clipboard"
            >
              <Clipboard size={16} />
            </button>
          </div>
        </div>

        {error && (
          <p className="text-red-500 text-sm">{error}</p>
        )}

        <div className="flex space-x-3">
          <button
            type="submit"
            disabled={isLoading || !url.trim()}
            className="flex-1 bg-blue-600 text-white py-3 px-6 rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center space-x-2"
          >
            <Search size={20} />
            <span>{isLoading ? 'Analyzing...' : 'Analyze URL'}</span>
          </button>
        </div>
      </form>

      <div className="mt-4 text-sm text-gray-600">
        <p className="mb-2">
          <span className="font-medium">Test URLs:</span>
        </p>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setUrl('https://google.com')}
            className="px-3 py-1 bg-gray-100 rounded-full hover:bg-gray-200 transition-colors"
          >
            Safe URL
          </button>
          <button
            onClick={() => setUrl('http://192.168.1.1/login@google.com')}
            className="px-3 py-1 bg-gray-100 rounded-full hover:bg-gray-200 transition-colors"
          >
            Suspicious URL
          </button>
          <button
            onClick={() => setUrl('https://secure-login.google-verify.tk/account/suspended')}
            className="px-3 py-1 bg-gray-100 rounded-full hover:bg-gray-200 transition-colors"
          >
            Malicious URL
          </button>
        </div>
      </div>
    </div>
  );
};