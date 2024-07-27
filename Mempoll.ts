import fs from "fs";
import path from "path";
import { Tx } from "./Tx";
import { TxIn } from "./TxIn";
import { Script } from "./Script";
import { TxOut } from "./TxOut";

export class Mempoll {
  public txs: Tx[];
  private folderPath = "./mempool";
  public feesArrayVector: bigint[];
  public txWeightVector: number[];

  constructor() {
    this.txs = [];
    this.feesArrayVector = [];
    this.txWeightVector = [];

    this.processDataSync();
  }

  private createTxFromJson = (data: any): Tx => {
    return new Tx(
      BigInt(data.version),
      data.vin.map((vin) => {
        let witness = [];

        if (TxIn.usesSegwit(vin)) {
          witness = Script.parseWitnessIntoCommand(vin.witness);
        }

        return new TxIn(
          vin.txid,
          BigInt(vin.vout),
          new Script([], vin.scriptsig),
          BigInt(vin.sequence),
          new Script([], vin.prevout.scriptpubkey),
          BigInt(vin.prevout.value),
          witness,
          vin.prevout.scriptpubkey_type
        );
      }),
      data.vout.map(
        (vout) =>
          new TxOut(BigInt(vout.value), new Script([], vout.scriptpubkey))
      ),
      BigInt(data.locktime),
      Tx.isSegwit(data.vin)
    );
  };

  private processDataSync() {
    try {
      const files = fs.readdirSync(this.folderPath);
      const jsonFiles = files.filter(
        (file) => path.extname(file).toLowerCase() === ".json"
      );

      for (const jsonFile of jsonFiles) {
        const filePath = path.join(this.folderPath, jsonFile);
        const data = fs.readFileSync(filePath, "utf8");
        const jsonData = JSON.parse(data);

        const flag = checkOnlyP2PKH(jsonData) || checkOnlyP2WPKH(jsonData);

        if (flag) {
          const newTx = this.createTxFromJson(jsonData);
          this.txs.push(newTx);
          this.txWeightVector.push(newTx.calculateWeight());
          this.feesArrayVector.push(newTx.fees());
        }
      }
    } catch (err) {
      console.error("Error processing mempool:", err);
    }
  }

  public updateMempool() {
    try {
      this.txs = [];
      this.feesArrayVector = [];
      this.txWeightVector = [];

      this.processDataSync();
      console.log("Mempool updated successfully.");
    } catch (err) {
      console.error("Error updating mempool:", err);
    }
  }

  public addTransaction(tx: Tx) {
    try {
      this.txs.push(tx);
      this.txWeightVector.push(tx.calculateWeight());
      this.feesArrayVector.push(tx.fees());
      console.log("Transaction added successfully.");
    } catch (err) {
      console.error("Error adding transaction:", err);
    }
  }

  public removeTransaction(txid: string) {
    try {
      const index = this.txs.findIndex((tx) => tx.getTxID() === txid);
      if (index === -1) {
        throw new Error("Transaction not found in mempool.");
      }

      this.txs.splice(index, 1);
      this.txWeightVector.splice(index, 1);
      this.feesArrayVector.splice(index, 1);
      console.log("Transaction removed successfully.");
    } catch (err) {
      console.error("Error removing transaction:", err);
    }
  }
}

const checkOnlyP2PKH = (jsonData: any) => {
  for (let i = 0; i < jsonData.vin.length; i++) {
    if (jsonData.vin[i].prevout.scriptpubkey_type != "p2pkh") {
      return false;
    }
  }
  return true;
};

const checkOnlyP2WPKH = (jsonData: any) => {
  for (let i = 0; i < jsonData.vin.length; i++) {
    if (jsonData.vin[i].prevout.scriptpubkey_type != "v0_p2wpkh") {
      return false;
    }
  }
  return true;
};

const mempool = new Mempoll();
mempool.updateMempool();

const newTxData = {
  version: 1,
  vin: [
    {
      txid: "abcd1234",
      vout: 0,
      scriptsig: "",
      sequence: 4294967295,
      prevout: {
        scriptpubkey: "",
        value: 1000,
        scriptpubkey_type: "p2pkh"
      },
      witness: [],
    }
  ],
  vout: [
    {
      value: 900,
      scriptpubkey: "",
    }
  ],
  locktime: 0,
};

const newTx = mempool.createTxFromJson(newTxData);
mempool.addTransaction(newTx);

const txidToRemove = newTx.getTxID();
mempool.removeTransaction(txidToRemove);
