import type { ButtonHTMLAttributes } from 'react'
import { cn } from '../../lib/utils'

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'quiet' | 'outline'
}

export function Button({ className, variant = 'primary', ...props }: ButtonProps) {
  return (
    <button
      className={cn(
        'inline-flex h-10 items-center justify-center gap-2 rounded-lg px-4 text-sm font-semibold transition duration-150 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--mint)] active:scale-[0.97] disabled:pointer-events-none disabled:opacity-50',
        variant === 'primary' && 'bg-[var(--mint)] text-[var(--ink)] shadow-[0_8px_24px_rgba(130,245,194,0.18)] hover:scale-[1.03] hover:bg-[#9bffd0] hover:shadow-[0_10px_28px_rgba(130,245,194,0.3)]',
        variant === 'quiet' && 'text-[var(--muted)] hover:scale-[1.02] hover:bg-white/[0.09] hover:text-white',
        variant === 'outline' && 'border border-white/10 bg-white/[0.03] text-white hover:scale-[1.03] hover:border-[var(--mint)]/45 hover:bg-white/[0.07]',
        className,
      )}
      {...props}
    />
  )
}
