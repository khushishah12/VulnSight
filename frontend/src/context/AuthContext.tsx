import React, { createContext, useContext, useEffect, useState } from "react";
import type { OperatorUser } from "../types";

interface AuthContextType {
  user: OperatorUser | null;
  isAuthenticated: boolean;
  login: (email: string, displayName?: string, role?: string) => void;
  logout: () => void;
}

const DEFAULT_OPERATOR: OperatorUser = {
  id: "sec-op-01",
  email: "secops@vulnsight.internal",
  display_name: "Security Engineer",
  role: "Lead Analyst",
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<OperatorUser | null>(() => {
    const saved = localStorage.getItem("vulnsight_user");
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        return DEFAULT_OPERATOR;
      }
    }
    return DEFAULT_OPERATOR;
  });

  useEffect(() => {
    if (user) {
      localStorage.setItem("vulnsight_user", JSON.stringify(user));
    } else {
      localStorage.removeItem("vulnsight_user");
    }
  }, [user]);

  function login(email: string, displayName = "Security Analyst", role = "Operator") {
    const newUser: OperatorUser = {
      id: `user-${Date.now()}`,
      email,
      display_name: displayName,
      role,
    };
    setUser(newUser);
  }

  function logout() {
    setUser(null);
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        login,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
