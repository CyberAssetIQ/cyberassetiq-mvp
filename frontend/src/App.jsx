import AppLayout from "./layouts/AppLayout";
import Dashboard from "./pages/Dashboard";
import "./style.css";

export default function App() {
  return (
    <AppLayout>
      <Dashboard />
    </AppLayout>
  );
}