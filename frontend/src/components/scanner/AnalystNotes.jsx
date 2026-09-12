import React, { useState } from 'react';
import { Edit3, Save, X, Trash2 } from 'lucide-react';
import { scansApi } from '../../services/api.js';
import toast from 'react-hot-toast';

export default function AnalystNotes({ scanId, initialNotes = '' }) {
  const [notes, setNotes] = useState(initialNotes || '');
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);

  const startEdit = () => {
    setDraft(notes);
    setEditing(true);
  };

  const cancelEdit = () => {
    setEditing(false);
    setDraft('');
  };

  const save = async () => {
    setSaving(true);
    try {
      await scansApi.updateNotes(scanId, draft.trim());
      setNotes(draft.trim());
      setEditing(false);
      toast.success('Analyst notes saved');
    } catch (err) {
      toast.error(err.message || 'Failed to save notes');
    } finally {
      setSaving(false);
    }
  };

  const deleteNotes = async () => {
    if (!window.confirm('Delete analyst notes? This cannot be undone.')) return;
    setSaving(true);
    try {
      await scansApi.updateNotes(scanId, '');
      setNotes('');
      toast.success('Notes deleted');
    } catch (err) {
      toast.error('Failed to delete notes');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      {!editing ? (
        <div>
          {notes ? (
            <div style={{ padding: '14px 16px', borderRadius: 10, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)', marginBottom: 12 }}>
              <p style={{ margin: 0, fontSize: 13, color: '#cbd5e1', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{notes}</p>
            </div>
          ) : (
            <p style={{ color: '#475569', fontSize: 13, fontStyle: 'italic', marginBottom: 12 }}>No analyst notes. Add investigation notes below.</p>
          )}
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn-ghost" onClick={startEdit} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Edit3 size={13} /> {notes ? 'Edit Notes' : 'Add Notes'}
            </button>
            {notes && (
              <button className="btn-danger" onClick={deleteNotes} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Trash2 size={13} /> Delete
              </button>
            )}
          </div>
        </div>
      ) : (
        <div>
          <textarea
            value={draft}
            onChange={e => setDraft(e.target.value)}
            placeholder="Add investigation notes, observations, findings..."
            maxLength={5000}
            style={{
              width: '100%', minHeight: 120,
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(0,194,255,0.3)',
              borderRadius: 10,
              padding: '12px 14px',
              color: '#f1f5f9',
              fontFamily: 'var(--font-sans)',
              fontSize: 13,
              lineHeight: 1.6,
              resize: 'vertical',
              outline: 'none',
              boxSizing: 'border-box',
            }}
          />
          <div style={{ display: 'flex', gap: 8, marginTop: 8, justifyContent: 'flex-end' }}>
            <button className="btn-ghost" onClick={cancelEdit}><X size={13} /> Cancel</button>
            <button className="btn-primary" onClick={save} disabled={saving}>
              <Save size={13} style={{ marginRight: 4, display: 'inline' }} />
              {saving ? 'Saving...' : 'Save Notes'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
