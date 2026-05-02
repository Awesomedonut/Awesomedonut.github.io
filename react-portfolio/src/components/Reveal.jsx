import { useReveal } from '../hooks/useReveal'

export function Reveal({ children, delay = 0, className = '' }) {
  const [ref, visible] = useReveal()

  return (
    <div
      ref={ref}
      className={`reveal ${visible ? 'visible' : ''} ${className}`}
      style={{ transitionDelay: `${delay}ms` }}
    >
      {children}
    </div>
  )
}
