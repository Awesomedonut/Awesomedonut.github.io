import './App.css'
import { Reveal } from './components/Reveal'

const projects = [
  {
    title: 'Falling Skies',
    desc: 'Educational iPad game built with a UBC research lab, plus a web dashboard displaying live gameplay data.',
    img: '/Printable1.jpg',
    tags: ['Client Work', 'Game Dev', 'Dashboard'],
    href: 'https://thecdm.ca/projects/falling-skies-25-ubc-alive-research-lab',
  },
  {
    title: 'CookSmart',
    desc: 'Multimedia AI app that generates recipes from text, image, and audio input.',
    img: '/cooksmart2.png',
    tags: ['AI/ML', 'Mobile', 'Multimodal'],
    href: 'https://sites.google.com/view/cmpt362cooksmart/home',
  },
  {
    title: 'ProBloom',
    desc: 'AI web app generating practice problems and auto-grading student answers across question formats.',
    img: '/probloom.png',
    tags: ['AI', 'EdTech', 'Full Stack'],
    href: 'https://github.com/Awesomedonut/Practice-Problem-Generator',
  },
  {
    title: 'H2O Yeah!',
    desc: 'Water tracking app UI prototype. Won both Class Favourite and Teaching Team Favourite awards.',
    img: '/h2ohyeah.png',
    tags: ['UI/UX', 'Prototype', 'Award Winner'],
    href: 'https://docs.google.com/presentation/d/1xvdoUYfw9DBAA-82ZlgMlVXCUApBvl633G8EC93c35I/edit?usp=sharing',
  },
]

const experience = [
  { date: 'Current', role: 'Software Engineering Intern', company: 'Tap n Tell AI', current: true },
  { date: 'Current', role: 'Software Engineering Contractor', company: 'iTOTEM Analytics', current: true },
  { date: '2025', role: 'Volunteer', company: 'SIGGRAPH 2025' },
  { date: '2024', role: 'Software Engineering Intern', company: 'Cryptoslam' },
  { date: '2024', role: 'Associate Writer', company: 'The Peak, SFU Student Newspaper' },
  { date: '2023', role: 'Software Engineering Intern', company: 'Cictan' },
  { date: '2023', role: 'HIVE Leader', company: 'Faculty of Applied Science, SFU' },
  { date: '2022–23', role: 'Asst. Director of Events → First Year Rep', company: 'Computing Science Student Society' },
]

function App() {
  return (
    <>
      {/* ── Nav ── */}
      <nav className="nav">
        <a href="#" className="nav-name">Jin Glebell</a>
        <div className="nav-links">
          <a href="#work" className="nav-link">Work</a>
          <a href="#experience" className="nav-link">Experience</a>
          <a href="#contact" className="nav-link">Contact</a>
        </div>
      </nav>

      <main className="container">
        {/* ── Hero ── */}
        <section className="hero" id="top">
          <div className="hero-inner">
            <div className="hero-text">
              <Reveal>
                <span className="hero-eyebrow">Software Developer + Artist</span>
              </Reveal>
              <Reveal delay={80}>
                <h1 className="hero-title">
                  I build things at the<br />
                  intersection of <em>art</em><br />
                  and <em>technology</em>
                </h1>
              </Reveal>
              <Reveal delay={160}>
                <p className="hero-sub">
                  Writer, developer, and aspiring animation studio founder.
                  I love combining creative thinking with engineering
                  to build experiences that feel alive.
                </p>
              </Reveal>
              <Reveal delay={240}>
                <div className="hero-cta-row">
                  <a href="#work" className="btn-primary">View projects ↓</a>
                  <a href="#contact" className="btn-ghost">Get in touch</a>
                </div>
              </Reveal>
            </div>
            <Reveal delay={200}>
              <div className="hero-img-wrap">
                <img
                  className="hero-img"
                  src="/pfp.png"
                  alt="Jin Glebell"
                />
                <span className="hero-img-badge">Open to work</span>
              </div>
            </Reveal>
          </div>
        </section>

        {/* ── Projects ── */}
        <section className="section" id="work">
          <Reveal>
            <div className="section-header">
              <div>
                <span className="section-eyebrow">Selected Work</span>
                <h2 className="section-title">Projects</h2>
              </div>
              <span className="section-count">{String(projects.length).padStart(2, '0')} projects</span>
            </div>
          </Reveal>
          <div className="projects-grid">
            {projects.map((p, i) => (
              <Reveal key={p.title} delay={i * 100}>
                <a
                  href={p.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="project-card"
                >
                  <div className="project-card-img-wrap">
                    <img className="project-card-img" src={p.img} alt={p.title} />
                  </div>
                  <div className="project-card-body">
                    <div className="project-card-tags">
                      {p.tags.map(t => (
                        <span key={t} className="project-tag">{t}</span>
                      ))}
                    </div>
                    <h3 className="project-card-title">{p.title}</h3>
                    <p className="project-card-desc">{p.desc}</p>
                    <span className="project-card-arrow">View project →</span>
                  </div>
                </a>
              </Reveal>
            ))}
          </div>
        </section>

        {/* ── Experience ── */}
        <section className="section" id="experience">
          <Reveal>
            <div className="section-header">
              <div>
                <span className="section-eyebrow">Background</span>
                <h2 className="section-title">Experience</h2>
              </div>
            </div>
          </Reveal>
          <div className="experience-list">
            {experience.map((e, i) => (
              <Reveal key={`${e.company}-${e.role}`} delay={i * 60}>
                <div className="experience-item">
                  <span className="experience-date">{e.date}</span>
                  <div className="experience-content">
                    <span className="experience-role">{e.role}</span>
                    <span className="experience-company">{e.company}</span>
                    {e.current && (
                      <span className="experience-badge">
                        <span className="experience-badge-dot" />
                        Current
                      </span>
                    )}
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
        </section>

        {/* ── Contact ── */}
        <Reveal>
          <section className="contact" id="contact">
            <span className="section-eyebrow">Get In Touch</span>
            <h2 className="contact-title">Let's work together</h2>
            <p className="contact-sub">
              I'd love to chat about opportunities, creative projects, or anything
              at the intersection of art and code.
            </p>
            <a href="mailto:yjs@sfu.ca" className="contact-email">yjs@sfu.ca</a>
            <div className="social-row">
              <a
                href="https://github.com/Awesomedonut"
                target="_blank"
                rel="noopener noreferrer"
                className="social-link"
                aria-label="GitHub"
              >
                <svg viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                </svg>
              </a>
              <a
                href="https://www.linkedin.com/in/jin-glebell/"
                target="_blank"
                rel="noopener noreferrer"
                className="social-link"
                aria-label="LinkedIn"
              >
                <svg viewBox="0 0 24 24" fill="currentColor">
                  <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                </svg>
              </a>
              <a
                href="https://linktr.ee/jin_glebell"
                target="_blank"
                rel="noopener noreferrer"
                className="social-link"
                aria-label="Linktree"
              >
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <line x1="12" y1="2.5" x2="12" y2="14" />
                  <line x1="3" y1="12" x2="21" y2="12" />
                  <line x1="5.64" y1="5.64" x2="18.36" y2="18.36" />
                  <line x1="18.36" y1="5.64" x2="5.64" y2="18.36" />
                  <rect x="10" y="14" width="4" height="8" fill="currentColor" stroke="none" rx="1" />
                </svg>
              </a>
            </div>
          </section>
        </Reveal>
      </main>

      {/* ── Footer ── */}
      <footer className="footer container">
        <span>Jin Glebell &copy; {new Date().getFullYear()}</span>
        <span className="footer-right">Built with React</span>
      </footer>
    </>
  )
}

export default App
