import React, { createContext, useContext, useEffect, useState } from "react";

export type AppRoute =
  | "landing"
  | "login"
  | "dashboard"
  | "new-scan"
  | "live-scan"
  | "scan-results"
  | "findings"
  | "finding-detail"
  | "remediation-center"
  | "verification-history"
  | "scan-history"
  | "reports"
  | "settings";

interface NavigationContextType {
  currentRoute: AppRoute;
  params: Record<string, string>;
  navigate: (route: AppRoute, params?: Record<string, string>) => void;
  breadcrumbs: { label: string; route?: AppRoute; params?: Record<string, string> }[];
}

const NavigationContext = createContext<NavigationContextType | undefined>(undefined);

export function NavigationProvider({ children }: { children: React.ReactNode }) {
  const [currentRoute, setCurrentRoute] = useState<AppRoute>("dashboard");
  const [params, setParams] = useState<Record<string, string>>({});

  useEffect(() => {
    // Synchronize initial URL hash or path
    function parseLocation() {
      const hash = window.location.hash.replace(/^#\/?/, "");
      if (!hash) return;

      const [routePart, queryString] = hash.split("?");
      const parsedParams: Record<string, string> = {};

      if (queryString) {
        new URLSearchParams(queryString).forEach((val, key) => {
          parsedParams[key] = val;
        });
      }

      if (routePart) {
        // match specific route patterns
        if (routePart.startsWith("scans/") && routePart.endsWith("/progress")) {
          const scanId = routePart.split("/")[1];
          setCurrentRoute("live-scan");
          setParams({ ...parsedParams, scanId });
        } else if (routePart.startsWith("scans/") && routePart !== "scans/new") {
          const scanId = routePart.split("/")[1];
          setCurrentRoute("scan-results");
          setParams({ ...parsedParams, scanId });
        } else if (routePart.startsWith("findings/")) {
          const findingId = routePart.split("/")[1];
          setCurrentRoute("finding-detail");
          setParams({ ...parsedParams, findingId });
        } else if (
          [
            "landing",
            "login",
            "dashboard",
            "new-scan",
            "findings",
            "remediation-center",
            "verification-history",
            "scan-history",
            "reports",
            "settings",
          ].includes(routePart)
        ) {
          setCurrentRoute(routePart as AppRoute);
          setParams(parsedParams);
        }
      }
    }

    parseLocation();
    window.addEventListener("hashchange", parseLocation);
    return () => window.removeEventListener("hashchange", parseLocation);
  }, []);

  function navigate(route: AppRoute, newParams: Record<string, string> = {}) {
    setCurrentRoute(route);
    setParams(newParams);

    // Update browser URL hash for persistent deep linking
    let hashTarget: string = route;
    if (route === "live-scan" && newParams.scanId) {
      hashTarget = `scans/${newParams.scanId}/progress`;
    } else if (route === "scan-results" && newParams.scanId) {
      hashTarget = `scans/${newParams.scanId}`;
    } else if (route === "finding-detail" && newParams.findingId) {
      hashTarget = `findings/${newParams.findingId}`;
    }

    const query = new URLSearchParams();
    Object.entries(newParams).forEach(([k, v]) => {
      if (k !== "scanId" && k !== "findingId") query.set(k, v);
    });
    const qStr = query.toString() ? `?${query.toString()}` : "";

    window.location.hash = `#/${hashTarget}${qStr}`;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  // Derive breadcrumbs
  const breadcrumbs: { label: string; route?: AppRoute; params?: Record<string, string> }[] = [
    { label: "SecOps Console", route: "dashboard" },
  ];

  if (currentRoute === "new-scan") {
    breadcrumbs.push({ label: "New Scan", route: "new-scan" });
  } else if (currentRoute === "scan-history") {
    breadcrumbs.push({ label: "Scan History", route: "scan-history" });
  } else if (currentRoute === "scan-results") {
    breadcrumbs.push({ label: "Scan History", route: "scan-history" });
    breadcrumbs.push({ label: `Scan ${params.scanId?.slice(0, 8) || ""}` });
  } else if (currentRoute === "live-scan") {
    breadcrumbs.push({ label: "Scan History", route: "scan-history" });
    breadcrumbs.push({ label: `Active Scan Progress` });
  } else if (currentRoute === "findings") {
    breadcrumbs.push({ label: "Vulnerability Findings", route: "findings" });
  } else if (currentRoute === "finding-detail") {
    breadcrumbs.push({ label: "Findings", route: "findings" });
    breadcrumbs.push({ label: `Finding ${params.findingId?.slice(0, 8) || ""}` });
  } else if (currentRoute === "remediation-center") {
    breadcrumbs.push({ label: "Remediation Center", route: "remediation-center" });
  } else if (currentRoute === "verification-history") {
    breadcrumbs.push({ label: "Fix Verification History", route: "verification-history" });
  } else if (currentRoute === "reports") {
    breadcrumbs.push({ label: "Security Reports", route: "reports" });
  } else if (currentRoute === "settings") {
    breadcrumbs.push({ label: "Settings", route: "settings" });
  } else if (currentRoute === "landing") {
    breadcrumbs.length = 0;
    breadcrumbs.push({ label: "Home", route: "landing" });
  }

  return (
    <NavigationContext.Provider value={{ currentRoute, params, navigate, breadcrumbs }}>
      {children}
    </NavigationContext.Provider>
  );
}

export function useNavigation() {
  const context = useContext(NavigationContext);
  if (!context) {
    throw new Error("useNavigation must be used within a NavigationProvider");
  }
  return context;
}
