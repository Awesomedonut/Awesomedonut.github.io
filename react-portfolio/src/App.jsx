import { useState, useEffect, useRef } from 'react'
import './App.css'

const sections = ['about', 'experience', 'projects']

const experience = [
  { date: 'Present', role: 'Software Engineering Intern', company: 'Tap n Tell AI', tags: ['React', 'TypeScript', 'AI'] },
  { date: 'Present', role: 'Software Engineering Contractor', company: 'iTOTEM Analytics', tags: ['Full Stack', 'Data'] },
  { date: '2025', role: 'Volunteer', company: 'SIGGRAPH 2025', tags: ['Computer Graphics', 'Community'] },
  { date: '2024', role: 'Software Engineering Intern', company: 'Cryptoslam', tags: ['Web3', 'Backend', 'APIs'] },
  { date: '2024', role: 'Associate Writer', company: 'The Peak', tags: ['Writing', 'Journalism'] },
  { date: '2023', role: 'Software Engineering Intern', company: 'Cictan', tags: ['Mobile', 'Full Stack'] },
  { date: '2023', role: 'HIVE Leader', company: 'SFU Applied Science', tags: ['Leadership', 'Mentorship'] },
  { date: '2022–23', role: 'Asst. Director of Events → First Year Rep', company: 'CSSS', tags: ['Events', 'Community'] },
]

const projects = [
  {
    title: 'Falling Skies',
    desc: 'Educational iPad game built with a UBC research lab, plus a web dashboard displaying live gameplay data.',
    img: '/Printable1.jpg',
    tags: ['Swift', 'React', 'Firebase'],
    href: 'https://thecdm.ca/projects/falling-skies-25-ubc-alive-research-lab',
  },
  {
    title: 'CookSmart',
    desc: 'Multimedia AI app that generates recipes from text, image, and audio input.',
    img: '/cooksmart2.png',
    tags: ['Kotlin', 'AI/ML', 'Android'],
    href: 'https://sites.google.com/view/cmpt362cooksmart/home',
  },
  {
    title: 'ProBloom',
    desc: 'AI web app generating practice problems and auto-grading student answers across question formats.',
    img: '/probloom.png',
    tags: ['Python', 'React', 'OpenAI'],
    href: 'https://github.com/Awesomedonut/Practice-Problem-Generator',
  },
  {
    title: 'H2O Yeah!',
    desc: 'Water tracking app UI prototype. Won both Class Favourite and Teaching Team Favourite awards.',
    img: '/h2ohyeah.png',
    tags: ['Figma', 'UI/UX', 'Prototype'],
    href: 'https://docs.google.com/presentation/d/1xvdoUYfw9DBAA-82ZlgMlVXCUApBvl633G8EC93c35I/edit?usp=sharing',
  },
]

function App() {
  const [activeSection, setActiveSection] = useState('about')
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 })
  const sectionRefs = useRef({})

  // Mouse spotlight
  useEffect(() => {
    const handleMouse = (e) => setMousePos({ x: e.clientX, y: e.clientY })
    window.addEventListener('mousemove', handleMouse)
    return () => window.removeEventListener('mousemove', handleMouse)
  }, [])

  // Active section tracking
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id)
          }
        })
      },
      { rootMargin: '-40% 0px -55% 0px' }
    )

    sections.forEach((id) => {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    })

    return () => observer.disconnect()
  }, [])

  const scrollTo = (id) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' })
  }

  return (
    <>
      {/* Spotlight */}
      <div
        className="spotlight"
        style={{
          background: `radial-gradient(600px circle at ${mousePos.x}px ${mousePos.y}px, rgba(29, 78, 216, 0.07), transparent 80%)`
        }}
      />

      <div className="layout">
        {/* ── Sidebar ── */}
        <header className="sidebar">
          <div className="sidebar-top">
            <h1 className="sidebar-name">Jin Song</h1>
            <h2 className="sidebar-title">Software Developer + Artist</h2>
            <p className="sidebar-desc">
              I build things at the intersection of art and technology.
            </p>
            <nav className="section-nav">
              {sections.map((s) => (
                <button
                  key={s}
                  className={`section-nav-link ${activeSection === s ? 'active' : ''}`}
                  onClick={() => scrollTo(s)}
                >
                  <span className="nav-indicator" />
                  {s}
                </button>
              ))}
            </nav>
          </div>
          <div className="social-links">
            <a href="https://github.com/Awesomedonut" target="_blank" rel="noopener noreferrer" className="social-icon" aria-label="GitHub">
              <svg viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
            </a>
            <a href="https://www.linkedin.com/in/jin-glebell/" target="_blank" rel="noopener noreferrer" className="social-icon" aria-label="LinkedIn">
              <svg viewBox="0 0 24 24"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>
            </a>
            <a href="https://linktr.ee/jin_glebell" target="_blank" rel="noopener noreferrer" className="social-icon" aria-label="Linktree">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="2.5" x2="12" y2="14" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="5.64" y1="5.64" x2="18.36" y2="18.36" /><line x1="18.36" y1="5.64" x2="5.64" y2="18.36" /><rect x="10" y="14" width="4" height="8" fill="currentColor" stroke="none" rx="1" /></svg>
            </a>
          </div>
        </header>

        {/* ── Main ── */}
        <main className="main-content">
          {/* About */}
          <section id="about" className="content-section">
            <div className="section-label">About</div>
            <div className="about-text">
              <p>
                I'm a software developer and artist who's obsessed with combining creative thinking
                with engineering. My journey started with drawing and storytelling, and now I channel
                that same energy into building software that feels alive.
              </p>
              <p>
                I've had the privilege of working at places like{' '}
                <a href="https://www.tapntell.ai/" target="_blank" rel="noopener noreferrer">an AI startup</a>,{' '}
                <a href="https://www.cryptoslam.io/" target="_blank" rel="noopener noreferrer">a Web3 data company</a>,{' '}
                and as a <a href="https://the-peak.ca/tag/jin-song/" target="_blank" rel="noopener noreferrer">published writer</a> at
                SFU's student newspaper.
              </p>
              <p>
                I enjoy writing code, fiction, and nonfiction — sometimes all in the same day.
                My dream is to found my own animation studio, and every project I take on is a
                step closer to that goal.
              </p>
              <p>
                When I'm not coding, you'll find me drawing, watching Studio Ghibli films, or
                volunteering at conferences like{' '}
                <a href="https://www.siggraph.org/" target="_blank" rel="noopener noreferrer">SIGGRAPH</a>.
              </p>
            </div>
          </section>

          {/* Experience */}
          <section id="experience" className="content-section">
            <div className="section-label">Experience</div>
            {experience.map((e) => (
              <div key={`${e.company}-${e.role}`} className="exp-card">
                <span className="exp-date">{e.date}</span>
                <div className="exp-body">
                  <div className="exp-role">
                    {e.role} · <span className="company-name">{e.company}</span>
                  </div>
                  <div className="exp-tags">
                    {e.tags.map((t) => (
                      <span key={t} className="exp-tag">{t}</span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </section>

          {/* Projects */}
          <section id="projects" className="content-section">
            <div className="section-label">Projects</div>
            <div className="proj-list">
              {projects.map((p) => (
                <a
                  key={p.title}
                  href={p.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="proj-card no-thumb"
                >
                  <div className="proj-body">
                    <div className="proj-title">
                      {p.title} <span className="arrow">↗</span>
                    </div>
                    <p className="proj-desc">{p.desc}</p>
                    <div className="proj-tags">
                      {p.tags.map((t) => (
                        <span key={t} className="exp-tag">{t}</span>
                      ))}
                    </div>
                  </div>
                </a>
              ))}
            </div>
          </section>

        </main>
      </div>
    </>
  )
}

export default App
