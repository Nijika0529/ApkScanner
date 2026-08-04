import * as DialogPrimitive from "@radix-ui/react-dialog"
import * as TabsPrimitive from "@radix-ui/react-tabs"
import { cva, type VariantProps } from "class-variance-authority"
import { X } from "lucide-react"
import type { ButtonHTMLAttributes, HTMLAttributes, PropsWithChildren } from "react"
import { cn } from "../lib"

const buttonVariants = cva(
  "inline-flex min-h-10 items-center justify-center gap-2 rounded-lg px-4 text-sm font-semibold transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700 focus-visible:ring-offset-2 focus-visible:ring-offset-white disabled:pointer-events-none disabled:opacity-45 motion-reduce:transition-none",
  {
    variants: {
      variant: {
        primary: "bg-cyan-700 text-white shadow-sm hover:bg-cyan-800",
        secondary: "border border-slate-300 bg-white text-slate-700 shadow-sm hover:border-slate-400 hover:bg-slate-50",
        ghost: "text-slate-600 hover:bg-slate-100 hover:text-slate-950",
        danger: "bg-rose-50 text-rose-700 ring-1 ring-inset ring-rose-200 hover:bg-rose-100",
      },
      size: { default: "h-10", sm: "h-9 min-h-9 px-3 text-xs", icon: "h-10 w-10 px-0" },
    },
    defaultVariants: { variant: "primary", size: "default" },
  },
)

export function Button({ className, variant, size, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof buttonVariants>) {
  return <button className={cn(buttonVariants({ variant, size }), className)} {...props} />
}

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-2xl border border-slate-200 bg-white shadow-[0_16px_45px_rgba(15,23,42,.07)]", className)} {...props} />
}

const badgeVariants = cva("inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold tracking-wide", {
  variants: {
    tone: {
      neutral: "border-slate-200 bg-slate-100 text-slate-700",
      good: "border-emerald-200 bg-emerald-50 text-emerald-700",
      warning: "border-amber-200 bg-amber-50 text-amber-800",
      danger: "border-rose-200 bg-rose-50 text-rose-700",
      info: "border-cyan-200 bg-cyan-50 text-cyan-800",
    },
  },
  defaultVariants: { tone: "neutral" },
})

export function Badge({ className, tone, ...props }: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />
}

export const Tabs = TabsPrimitive.Root
export function TabsList(props: TabsPrimitive.TabsListProps) {
  return <TabsPrimitive.List className="flex w-full gap-1 overflow-x-auto border-b border-slate-200" {...props} />
}
export function TabsTrigger({ className, ...props }: TabsPrimitive.TabsTriggerProps) {
  return <TabsPrimitive.Trigger className={cn("min-h-11 shrink-0 border-b-2 border-transparent px-4 text-sm font-medium text-slate-500 outline-none transition-colors hover:text-slate-900 focus-visible:ring-2 focus-visible:ring-cyan-700 data-[state=active]:border-cyan-700 data-[state=active]:text-cyan-800", className)} {...props} />
}
export function TabsContent({ className, ...props }: TabsPrimitive.TabsContentProps) {
  return <TabsPrimitive.Content className={cn("pt-6 outline-none focus-visible:ring-2 focus-visible:ring-cyan-700", className)} {...props} />
}

export const Dialog = DialogPrimitive.Root
export const DialogTrigger = DialogPrimitive.Trigger
export function DialogContent({ children, className, ...props }: PropsWithChildren<DialogPrimitive.DialogContentProps>) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-slate-900/35 backdrop-blur-sm data-[state=open]:animate-in" />
      <DialogPrimitive.Content className={cn("fixed left-1/2 top-1/2 z-50 max-h-[90vh] w-[calc(100%-2rem)] max-w-xl -translate-x-1/2 -translate-y-1/2 overflow-auto rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl outline-none focus-visible:ring-2 focus-visible:ring-cyan-700", className)} {...props}>
        {children}
        <DialogPrimitive.Close className="absolute right-4 top-4 rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-950 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-700" aria-label="关闭对话框">
          <X className="h-4 w-4" />
        </DialogPrimitive.Close>
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  )
}
export const DialogTitle = DialogPrimitive.Title
export const DialogDescription = DialogPrimitive.Description

export function Progress({ value, label }: { value: number; label: string }) {
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-xs text-slate-600"><span>{label}</span><span>{Math.round(value)}%</span></div>
      <div className="h-2 overflow-hidden rounded-full bg-slate-200" role="progressbar" aria-label={label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(value)}>
        <div className="h-full rounded-full bg-gradient-to-r from-cyan-700 to-emerald-500 transition-[width] duration-500 motion-reduce:transition-none" style={{ width: `${Math.max(0, Math.min(value, 100))}%` }} />
      </div>
    </div>
  )
}
