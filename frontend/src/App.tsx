import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import Analytics from "./pages/Analytics";
import Findings from "./pages/Findings";
import Overview from "./pages/Overview";
import RunDetail from "./pages/RunDetail";
import Scans from "./pages/Scans";
import Settings from "./pages/Settings";

export default function App() {
  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Overview />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/runs/:runId" element={<RunDetail />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/analytics" element={<Analytics />} />
        <Route path="/settings" element={<Settings />} />
      </Routes>
    </Layout>
  );
}

