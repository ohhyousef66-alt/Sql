import { Link } from "wouter";
import { AlertTriangle } from "lucide-react";

export default function NotFound() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background text-foreground">
      <div className="text-center space-y-6 p-8 border border-border bg-card rounded-2xl shadow-2xl max-w-md mx-4">
        <div className="w-20 h-20 bg-destructive/10 rounded-full flex items-center justify-center mx-auto">
           <AlertTriangle className="h-10 w-10 text-destructive" />
        </div>
        
        <div className="space-y-2">
          <h1 className="text-4xl font-bold font-display">404</h1>
          <p className="text-xl font-medium">Page Not Found</p>
          <p className="text-muted-foreground text-sm">
            The resource you are looking for does not exist or has been moved.
          </p>
        </div>

        <Link href="/" className="inline-block w-full py-3 px-4 bg-primary text-primary-foreground font-bold rounded-lg hover:opacity-90 transition-opacity">
          Return to Dashboard
        </Link>
      </div>
    </div>
  );
}
