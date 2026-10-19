import { useState } from "react";

/**
 * A search input that submits on Enter. Mount it with ``key={value}`` so it resets when the URL changes
 * (no effect needed to synchronise local state).
 */
export function SearchField({
  id,
  label,
  initial,
  placeholder,
  onSubmit,
  className,
}: {
  id: string;
  label: string;
  initial: string;
  placeholder?: string;
  onSubmit: (value: string) => void;
  className?: string;
}) {
  const [value, setValue] = useState(initial);
  return (
    <form
      className={className}
      onSubmit={(event) => {
        event.preventDefault();
        onSubmit(value.trim());
      }}
    >
      <label htmlFor={id} className="label">
        {label}
      </label>
      <input
        id={id}
        className="input"
        value={value}
        placeholder={placeholder}
        onChange={(event) => {
          setValue(event.target.value);
        }}
      />
    </form>
  );
}
