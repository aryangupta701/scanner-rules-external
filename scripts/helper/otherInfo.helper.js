/**
 * 
 */
class MetaData {
    constructor(bountyUsd, bountyDescription ,bountyReferenceUrl, totalTestCases, cvss31Numeric, cvss31Vector, fetchFromAlert){
        this.bountyUsd = bountyUsd || 0;
        this.bountyDescription = bountyDescription || "";
        this.bountyReferenceUrl = bountyReferenceUrl || "";
        this.totalTestCases = totalTestCases || 1;
        this.cvss31Numeric = cvss31Numeric || null;
        this.cvss31Vector = cvss31Vector || null;
        this.fetchFromAlert = fetchFromAlert || false;
    }

    set setBounty(value){
        this.bountyUsd = value;
    }

    set setBountyDescription(value){
        this.bountyDescription = value;
    }

    set setBountyReferenceUrl(value){
        this.bountyReferenceUrl = value;
    }

    set setTotalTestCases(value){
        this.totalTestCases = value;
    }

    set setCvss31Numeric(value){
        this.cvss31Numeric = value;
    }

    set setCvss31Vector(value){
        this.cvss31Vector = value;
    }

    set setFetchFromAlert(value){
        this.fetchFromAlert = value;
    }

    get json(){
        var metaData = Object.fromEntries(Object.entries(this).filter(([_, v]) => v != null));
        return JSON.stringify(metaData);
    }
}