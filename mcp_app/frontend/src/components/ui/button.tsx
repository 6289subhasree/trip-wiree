import * as React from "react";

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "default" | "secondary" | "destructive" | "outline" | "ghost";
  size?: "default" | "sm" | "lg" | "icon";
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className = "", variant = "default", size = "default", ...props }, ref) => {
    let variantStyles = "bg-[#5e6ad2] text-white hover:bg-[#828fff] shadow-[0_0_12px_rgba(94,106,210,0.3)]";
    if (variant === "secondary") {
      variantStyles = "bg-[#141516] text-[#d0d6e0] border border-[#23252a] hover:bg-[#191a1b] hover:text-white";
    } else if (variant === "destructive") {
      variantStyles = "bg-red-950/40 text-[#ef4444] border border-red-800/40 hover:bg-red-900/60";
    } else if (variant === "outline") {
      variantStyles = "border border-[#23252a] text-[#d0d6e0] hover:bg-[#141516] hover:text-white";
    } else if (variant === "ghost") {
      variantStyles = "text-[#8a8f98] hover:bg-[#141516] hover:text-white";
    }

    let sizeStyles = "h-9 px-4 py-2 text-xs";
    if (size === "sm") {
      sizeStyles = "h-7 px-2.5 text-[11px]";
    } else if (size === "lg") {
      sizeStyles = "h-11 px-6 text-sm";
    } else if (size === "icon") {
      sizeStyles = "h-8 w-8 p-0 flex items-center justify-center";
    }

    return (
      <button
        ref={ref}
        className={`inline-flex items-center justify-center rounded-md font-medium transition-all focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#5e6ad2] disabled:pointer-events-none disabled:opacity-40 cursor-pointer ${variantStyles} ${sizeStyles} ${className}`}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";
