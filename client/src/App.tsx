import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import NotFound from "@/pages/not-found";
import Home from "@/pages/Home";
import NewScan from "@/pages/NewScan";
import BatchScan from "@/pages/BatchScan";
import MassScan from "@/pages/MassScan";
import ScanDetails from "@/pages/ScanDetails";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/scans/new" component={NewScan} />
      <Route path="/scans/batch" component={BatchScan} />
      <Route path="/scans/mass" component={MassScan} />
      <Route path="/scans/:id" component={ScanDetails} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
