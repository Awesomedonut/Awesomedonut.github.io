import { useState, useRef } from 'react'
import './BrowserShell.css'

export function BrowserShell({ children }) {
  const [url, setUrl] = useState('https://jinglebell.dev')
  const [isUrlFocused, setIsUrlFocused] = useState(false)
  const urlRef = useRef(null)

  return (
    <div className="browser-shell">
      {/* Title bar + tabs */}
      <div className="shell-title-bar">
        <div className="shell-traffic-lights">
          <span className="shell-light close" />
          <span className="shell-light minimize" />
          <span className="shell-light maximize" />
        </div>
        <div className="shell-tab-bar">
          <div className="shell-tab active">
            <span className="shell-tab-title">Jin Glebell — Portfolio</span>
          </div>
          <button className="shell-new-tab" aria-label="New tab">
            <svg width="11" height="11" viewBox="0 0 12 12">
              <path d="M6 1v10M1 6h10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </div>
      </div>

      {/* Navigation bar */}
      <div className="shell-nav-bar">
        <div className="shell-nav-controls">
          <button className="shell-nav-btn" aria-label="Back">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="15 18 9 12 15 6" />
            </svg>
          </button>
          <button className="shell-nav-btn" aria-label="Forward">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="9 18 15 12 9 6" />
            </svg>
          </button>
          <button className="shell-nav-btn" aria-label="Reload">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="23 4 23 10 17 10" />
              <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
            </svg>
          </button>
        </div>

        <div className={`shell-url-bar ${isUrlFocused ? 'focused' : ''}`}>
          <svg className="shell-url-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0 1 10 0v4" />
          </svg>
          <input
            ref={urlRef}
            className="shell-url-input"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onFocus={() => {
              setIsUrlFocused(true)
              setTimeout(() => urlRef.current?.select(), 0)
            }}
            onBlur={() => setIsUrlFocused(false)}
            spellCheck={false}
          />
        </div>

        <div className="shell-nav-actions">
          <button className="shell-nav-btn" aria-label="Share">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8" />
              <polyline points="16 6 12 2 8 6" />
              <line x1="12" y1="2" x2="12" y2="15" />
            </svg>
          </button>
          <button className="shell-nav-btn" aria-label="Menu">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="1" />
              <circle cx="12" cy="5" r="1" />
              <circle cx="12" cy="19" r="1" />
            </svg>
          </button>
        </div>
      </div>

      {/* Bookmarks bar */}
      <div className="shell-bookmarks">
        <span className="shell-bookmark">
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" /></svg>
          Portfolio
        </span>
        <span className="shell-bookmark">GitHub</span>
        <span className="shell-bookmark">LinkedIn</span>
        <span className="shell-bookmark">The Peak</span>
        <span className="shell-bookmark">YouTube</span>
      </div>

      {/* Content */}
      <div className="shell-content">
        {children}
      </div>
    </div>
  )
}
