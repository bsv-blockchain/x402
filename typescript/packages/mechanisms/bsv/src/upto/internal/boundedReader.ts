import { Utils } from "@bsv/sdk";

/** Adds strict bounds to SDK primitives while leaving the BEEF grammar to the SDK. */
export class BoundedReader extends Utils.ReaderUint8Array {
  /** @inheritdoc */
  override read(length = this.bin.length - this.pos): Uint8Array {
    this.ensureAvailable(length);
    return super.read(length);
  }

  /** @inheritdoc */
  override readReverse(length = this.bin.length - this.pos): Uint8Array {
    this.ensureAvailable(length);
    return super.readReverse(length);
  }

  /** @inheritdoc */
  override readUInt8(): number {
    this.ensureAvailable(1);
    return super.readUInt8();
  }

  /** @inheritdoc */
  override readInt8(): number {
    this.ensureAvailable(1);
    return super.readInt8();
  }

  /** @inheritdoc */
  override readUInt16BE(): number {
    this.ensureAvailable(2);
    return super.readUInt16BE();
  }

  /** @inheritdoc */
  override readUInt16LE(): number {
    this.ensureAvailable(2);
    return super.readUInt16LE();
  }

  /** @inheritdoc */
  override readUInt32BE(): number {
    this.ensureAvailable(4);
    return super.readUInt32BE();
  }

  /** @inheritdoc */
  override readUInt32LE(): number {
    this.ensureAvailable(4);
    return super.readUInt32LE();
  }

  /**
   * Rejects a primitive read that would cross the captured byte array.
   *
   * @param length - Requested byte count
   */
  private ensureAvailable(length: number): void {
    if (!Number.isSafeInteger(length) || length < 0 || this.pos > this.bin.length - length) {
      throw new RangeError("read exceeds Atomic BEEF bounds");
    }
  }
}
