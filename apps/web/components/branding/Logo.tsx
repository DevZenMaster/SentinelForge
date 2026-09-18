import React from 'react';
import Image from 'next/image';
import Link from 'next/link';
import { cn } from '@/lib/utils';

export type LogoVariant = 'full' | 'mark';
export type LogoSize = 'sm' | 'md' | 'lg' | 'xl' | 'custom';

export interface LogoProps {
  /**
   * 'full' renders the full logo (shield emblem + SentinelForge typography).
   * 'mark' renders only the shield emblem (ideal for favicons, mobile headers, or collapsed sidebars).
   */
  variant?: LogoVariant;
  /**
   * Preset size or 'custom' to control sizing exclusively via className.
   */
  size?: LogoSize;
  /**
   * Accessible text for screen readers and SEO. Defaults to 'SentinelForge'.
   */
  alt?: string;
  /**
   * Optional wrapping link URL (e.g. '/dashboard').
   */
  href?: string;
  /**
   * Optimize above-the-fold display (e.g. on login page or layout headers).
   */
  priority?: boolean;
  /**
   * Optional additional CSS classes.
   */
  className?: string;
}

const fullSizeClasses: Record<Exclude<LogoSize, 'custom'>, string> = {
  sm: 'h-8 w-auto',
  md: 'h-10 w-auto',
  lg: 'h-[50px] w-auto',
  xl: 'h-[72px] w-auto',
};

const markSizeClasses: Record<Exclude<LogoSize, 'custom'>, string> = {
  sm: 'h-8 w-8',
  md: 'h-10 w-10',
  lg: 'h-[50px] w-[50px]',
  xl: 'h-[72px] w-[72px]',
};

export const Logo: React.FC<LogoProps> = ({
  variant = 'full',
  size = 'md',
  alt = 'SentinelForge',
  href,
  priority = false,
  className,
}) => {
  const isFull = variant === 'full';
  const src = isFull ? '/branding/logo.png' : '/branding/logo-mark.png';
  const width = isFull ? 790 : 140;
  const height = isFull ? 316 : 140;

  const sizeClass =
    size !== 'custom'
      ? isFull
        ? fullSizeClasses[size]
        : markSizeClasses[size]
      : '';

  const imageElement = (
    <Image
      src={src}
      alt={alt}
      width={width}
      height={height}
      priority={priority}
      unoptimized
      className={cn('object-contain select-none transition-opacity', sizeClass, className)}
    />
  );

  if (href) {
    return (
      <Link
        href={href}
        className="inline-flex items-center focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 rounded"
        aria-label={alt}
      >
        {imageElement}
      </Link>
    );
  }

  return imageElement;
};

export default Logo;
