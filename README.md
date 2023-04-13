# Patch Diffing In The Dark

A series of blog posts leveraging CVE analysis and patch diffing to discover new vulnerabilities.

As revealed in the blog posts, the following 4 CVEs came from the in-depth study of CVE-2021-1657.

## TOC

- [Part 1 - Patch Diffing In The Dark](Patch%20Diffing%20In%20the%20Dark%20-%20CVE-2021-1657.md)
- [Part 2 - Down the Rabbit Hole](Patch%20Diffing%20in%20the%20Dark%20-%20CVE-2021-1657%20-%20Part%202%20-%20Down%20the%20Rabbit%20Hole.md)
- [Part 3 - Down But Not Out](Patch%20Diffing%20in%20the%20Dark%20-%20CVE-2021-1657%20-%20Part%203%20-%20Down%20But%20Not%20Out.md)
- [Part 4 - Do You Trust Me?](Patch%20Diffing%20in%20the%20Dark%20-%20CVE-2021-1657%20-%20Part%204%20-%20Do%20you%20trust%20me.md)

## CVE Mapping

| CVE                                                                                          | Description                  | Type                                      | Blog Reference                                                                                                                                                                                         |
| -------------------------------------------------------------------------------------------- | ---------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [CVE-2022-26916](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-26916) | Windows Fax Compose Form RCE | Heap Buffer Overflow via Integer Overflow | [Found](Patch%20Diffing%20in%20the%20Dark%20-%20CVE-2021-1657%20-%20Part%202%20-%20Down%20the%20Rabbit%20Hole.md#integer-overflow-found)                                                               |
| [CVE-2022-26917](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-26917) | Windows Fax Compose Form RCE | Heap Buffer Overflow via Integer Overflow | [CVE-2021-XXXX](Patch%20Diffing%20in%20the%20Dark%20-%20CVE-2021-1657%20-%20Part%203%20-%20Down%20But%20Not%20Out.md#cve-2021-xxxx-heap-buffer-overflow-via-integer-overflow---cwabalhrbuildhglobal)   |
| [CVE-2022-26918](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-26918) | Windows Fax Compose Form RCE | Deserialization of Untrusted Data         | [CVE-2021-ZZZZ](Patch%20Diffing%20in%20the%20Dark%20-%20CVE-2021-1657%20-%20Part%203%20-%20Down%20But%20Not%20Out.md#cve-2021-yyyy-heap-buffer-overflow-via-integer-overflow---wab32scmergepropvalues) |
| [CVE-2022-26926](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-26926) | Windows Address Book RCE     | Heap Buffer Overflow via Integer Overflow | [CVE-2021-YYYY](Patch%20Diffing%20in%20the%20Dark%20-%20CVE-2021-1657%20-%20Part%203%20-%20Down%20But%20Not%20Out.md#cve-2021-yyyy-heap-buffer-overflow-via-integer-overflow---wab32scmergepropvalues) |


## Background

*This research was performed by a CSE Vulnerability Researcher under CSE's mandate to discover vulnerabilities and protect Canadian Government Networks and Systems. This research resulted in the discovery of several vulnerabilities which were reviewed as per [CSE's Equities Management Framework](https://www.cse-cst.gc.ca/en/information-and-resources/announcements/cses-equities-management-framework) and submitted to Microsoft's Security Response Center.  The findings were published as CVE-2022-26917, CVE-2022-26917, CVE-2022-26918, and CVE-2022-26926. This work demonstrates just one method of vulnerability discovery from start to finish.  If this type of work interests you, consider applying to [CSE's VRC](https://www.cse-cst.gc.ca/en/mission/research-cse/vulnerability-research-centre). Complete CSE's general application and select “Vulnerability Research Engineer” as the job type. If you have any questions or wish to provide additional information for your application, please email vrc-crv@cse-cst.gc.ca ([PGP Key](https://raw.githubusercontent.com/VulnerabilityResearchCentre/.github/main/profile/Vulnerability%20Research%20Centre.asc)).*
