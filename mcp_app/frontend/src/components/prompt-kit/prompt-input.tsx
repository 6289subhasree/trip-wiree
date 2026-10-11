"use client";

import * as React from "react";

interface PromptInputContextType {
  value: string;
  onValueChange: (val: string) => void;
  isLoading?: boolean;
  onSubmit?: () => void;
}

const PromptInputContext = React.createContext<PromptInputContextType | null>(null);

export interface PromptInputProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
  onValueChange: (val: string) => void;
  isLoading?: boolean;
  onSubmit?: () => void;
  children: React.ReactNode;
}

export function PromptInput({
  value,
  onValueChange,
  isLoading,
  onSubmit,
  className = "",
  children,
  ...props
}: PromptInputProps) {
  return (
    <PromptInputContext.Provider value={{ value, onValueChange, isLoading, onSubmit }}>
      <div
        className={`relative flex flex-col w-full rounded-2xl bg-[#0f1011] border border-[#23252a] p-3 transition-all duration-200 focus-within:border-[#5e6ad2] focus-within:ring-1 focus-within:ring-[#5e6ad2]/40 shadow-xl ${className}`}
        {...props}
      >
        {children}
      </div>
    </PromptInputContext.Provider>
  );
}

export interface PromptInputTextareaProps
  extends React.TextareaHTMLAttributes<HTMLTextAreaElement> {}

export function PromptInputTextarea({
  placeholder = "Ask me anything...",
  className = "",
  ...props
}: PromptInputTextareaProps) {
  const context = React.useContext(PromptInputContext);
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      context?.onSubmit?.();
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    context?.onValueChange?.(e.target.value);
    // Auto resize
    if (textareaRef.current) {
      textareaRef.current.style.height = "auto";
      textareaRef.current.style.height = `${Math.min(textareaRef.current.scrollHeight, 180)}px`;
    }
  };

  React.useEffect(() => {
    if (textareaRef.current && context?.value === "") {
      textareaRef.current.style.height = "auto";
    }
  }, [context?.value]);

  return (
    <textarea
      ref={textareaRef}
      value={context?.value || ""}
      onChange={handleChange}
      onKeyDown={handleKeyDown}
      placeholder={placeholder}
      rows={1}
      className={`w-full bg-transparent text-[#f7f8f8] placeholder-[#62666d] text-xs md:text-sm font-sans focus:outline-none resize-none leading-relaxed min-h-[36px] max-h-[180px] overflow-y-auto ${className}`}
      {...props}
    />
  );
}

export interface PromptInputActionsProps
  extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
}

export function PromptInputActions({
  className = "",
  children,
  ...props
}: PromptInputActionsProps) {
  return (
    <div
      className={`flex items-center justify-between gap-2 pt-2 border-t border-[#23252a]/50 ${className}`}
      {...props}
    >
      {children}
    </div>
  );
}

export interface PromptInputActionProps
  extends React.HTMLAttributes<HTMLDivElement> {
  tooltip?: string;
  children: React.ReactNode;
}

export function PromptInputAction({
  tooltip,
  className = "",
  children,
  ...props
}: PromptInputActionProps) {
  return (
    <div
      title={tooltip}
      className={`relative inline-flex items-center justify-center ${className}`}
      {...props}
    >
      {children}
    </div>
  );
}
