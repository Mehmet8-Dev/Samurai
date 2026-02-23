import { useState } from "react";
import { Button, InputField, SelectField } from "../../../shared/ui";

export const initialTestForm = {
  target: "127.0.0.1",
  port: 80,
  protocol: "tcp",
  attack_vector: "basic",
  count: 1000,
  duration: 30,
  workers: 2,
  rps: 0,
  backend: "cpu",
  allow_public_target: false,
};

export function StartTestForm({ onSubmit, disabled, mode = "compact" }) {
  const [form, setForm] = useState(initialTestForm);
  const [error, setError] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError("");

    if (!form.target.trim()) {
      setError("Target zorunludur.");
      return;
    }

    if (Number(form.port) <= 0 || Number(form.port) > 65535) {
      setError("Port 1-65535 aralığında olmalıdır.");
      return;
    }

    if (Number(form.count) < 1) {
      setError("Count en az 1 olmalıdır.");
      return;
    }

    if (Number(form.duration) < 1) {
      setError("Duration en az 1 olmalıdır.");
      return;
    }

    const payload = {
      ...form,
      port: Number(form.port),
      count: Number(form.count),
      duration: Number(form.duration),
      workers: Number(form.workers),
      rps: Number(form.rps),
    };

    await onSubmit(payload);
  };

  const columnsClass = mode === "expanded" ? "columns-3" : "columns-2";

  return (
    <form className="stack" onSubmit={handleSubmit} aria-label="Test başlatma formu">
      <section className={`form-grid ${columnsClass}`.trim()}>
        <InputField
          id="test-target"
          label="Target"
          density="compact"
          value={form.target}
          onChange={(event) => setForm((state) => ({ ...state, target: event.target.value }))}
          required
        />

        <InputField
          id="test-port"
          label="Port"
          type="number"
          density="compact"
          value={form.port}
          onChange={(event) => setForm((state) => ({ ...state, port: event.target.value }))}
        />

        <SelectField
          id="test-protocol"
          label="Protocol"
          density="compact"
          value={form.protocol}
          onChange={(event) => setForm((state) => ({ ...state, protocol: event.target.value }))}
          options={[
            { value: "tcp", label: "tcp" },
            { value: "udp", label: "udp" },
            { value: "icmp", label: "icmp" },
          ]}
        />

        <InputField
          id="test-vector"
          label="Attack Vector"
          density="compact"
          value={form.attack_vector}
          onChange={(event) => setForm((state) => ({ ...state, attack_vector: event.target.value }))}
        />

        <InputField
          id="test-count"
          label="Count"
          type="number"
          density="compact"
          value={form.count}
          onChange={(event) => setForm((state) => ({ ...state, count: event.target.value }))}
        />

        <InputField
          id="test-duration"
          label="Duration (s)"
          type="number"
          density="compact"
          value={form.duration}
          onChange={(event) => setForm((state) => ({ ...state, duration: event.target.value }))}
        />
      </section>

      <div className="row-between">
        <Button
          type="button"
          variant="quiet"
          size="sm"
          onClick={() => setShowAdvanced((current) => !current)}
          aria-expanded={showAdvanced}
          aria-controls="advanced-test-fields"
        >
          {showAdvanced ? "Gelişmiş Alanları Gizle" : "Gelişmiş Ayarlar"}
        </Button>

        <Button type="submit" variant="primary" disabled={disabled}>
          {disabled ? "İşleniyor..." : "Test Başlat"}
        </Button>
      </div>

      {showAdvanced ? (
        <section id="advanced-test-fields" className={`form-grid ${columnsClass}`.trim()}>
          <InputField
            id="test-workers"
            label="Workers"
            type="number"
            density="compact"
            value={form.workers}
            onChange={(event) => setForm((state) => ({ ...state, workers: event.target.value }))}
          />

          <InputField
            id="test-rps"
            label="RPS"
            type="number"
            density="compact"
            value={form.rps}
            onChange={(event) => setForm((state) => ({ ...state, rps: event.target.value }))}
          />

          <SelectField
            id="test-backend"
            label="Backend"
            density="compact"
            value={form.backend}
            onChange={(event) => setForm((state) => ({ ...state, backend: event.target.value }))}
            options={[
              { value: "cpu", label: "cpu" },
              { value: "cuda", label: "cuda" },
            ]}
          />

          <label className="checkbox-field" htmlFor="test-allow-public">
            <input
              id="test-allow-public"
              type="checkbox"
              checked={form.allow_public_target}
              onChange={(event) => setForm((state) => ({ ...state, allow_public_target: event.target.checked }))}
            />
            Allow Public Target
          </label>
        </section>
      ) : null}

      {error ? <p role="alert" className="form-error-summary">{error}</p> : null}
    </form>
  );
}
