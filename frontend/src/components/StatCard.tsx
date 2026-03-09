import type { ReactNode } from "react";

export default function StatCard({
  title,
  value,
  icon,
  tone,
}: {
  title: string;
  value: ReactNode;
  icon?: ReactNode;
  tone?: "default" | "good" | "warn" | "bad";
}) {
  return (
    <div className="card">
      <div className="cardTitle">{title}</div>
      <div className="kpiRow">
        <div className="cardValue">{value}</div>
        {icon ? <div className={`kpiIcon ${tone ?? "default"}`}>{icon}</div> : null}
      </div>
    </div>
  );
}
