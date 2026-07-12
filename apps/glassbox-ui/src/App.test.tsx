import React from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it } from 'vitest';
import { GlassboxApp } from './App';

afterEach(cleanup);

describe('Glassbox investigation workbench', () => {
  it('keeps a complete tabular alternative available', async () => {
    const user = userEvent.setup();
    render(<GlassboxApp />);
    expect(screen.getByRole('table', { name: /complete tabular equivalent/i })).toBeTruthy();
    await user.click(screen.getByRole('tab', { name: /table/i }));
    expect(screen.queryByLabelText(/actor-lane evidence timeline/i)).toBeNull();
    expect(screen.getByText('Click “Upload”')).toBeTruthy();
  });

  it('updates selected evidence and opens field-level export review', async () => {
    const user = userEvent.setup();
    render(<GlassboxApp />);
    fireEvent.click(screen.getAllByText('Memory pressure: high')[0]!);
    expect(screen.getByText(/Selected: Memory pressure: high/)).toBeTruthy();
    await user.click(screen.getByRole('button', { name: /export review/i }));
    expect(screen.getByRole('dialog', { name: /export \/ redaction preview/i })).toBeTruthy();
    expect(screen.getByText('Structural redaction')).toBeTruthy();
  });

  it('shows uncertainty, counterevidence, and missing evidence without a causal claim', () => {
    render(<GlassboxApp />);
    expect(screen.getByText(/candidate relation, not causation/i)).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Counterevidence' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Missing evidence' })).toBeTruthy();
    expect(screen.getByText(/no causal conclusion/i)).toBeTruthy();
  });
});
