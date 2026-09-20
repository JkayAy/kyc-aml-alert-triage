/**
 * sar-stub.ts
 *
 * Stub implementation of the SAR (Suspicious Activity Report) filing API.
 * Replace this module with your jurisdiction's actual reporting endpoint.
 */

export interface SarPayload {
  alertId: string;
  typologyLabel: string;
  rationale: string;
  analystId: string;
  decidedAt: string;
}

export interface SarReceipt {
  sarReferenceNumber: string;
  filedAt: string;
}

export async function fileSar(payload: SarPayload): Promise<SarReceipt> {
  // TODO: replace with your jurisdiction's SAR filing API
  // e.g. UK NCA UKFIU gateway, FinCEN BSA E-Filing, FATF goAML
  console.info('[sar-stub] SAR filing stub called', { alertId: payload.alertId });
  await new Promise((resolve) => setTimeout(resolve, 50));
  return {
    sarReferenceNumber: `STUB-${Date.now()}-${payload.alertId.slice(0, 8).toUpperCase()}`,
    filedAt: new Date().toISOString(),
  };
}
