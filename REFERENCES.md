# References

## Methods and threat context

1. Fei Tony Liu, Kai Ming Ting, and Zhi-Hua Zhou. *Isolation Forest.*
   2008 IEEE International Conference on Data Mining.
   <https://ieeexplore.ieee.org/document/4781136>

2. Markus M. Breunig, Hans-Peter Kriegel, Raymond T. Ng, and Jörg Sander.
   *LOF: Identifying Density-Based Local Outliers.* ACM SIGMOD 2000.
   <https://dl.acm.org/doi/10.1145/335191.335388>

3. Leo Breiman. *Random Forests.* Machine Learning, 2001.
   <https://doi.org/10.1023/A:1010933404324>

4. MITRE ATT&CK, technique T1486: *Data Encrypted for Impact.*
   <https://attack.mitre.org/techniques/T1486/>

## Real data sources (for the next pass off synthetic data)

The current results are on generated telemetry. The real, public Sysmon / endpoint
telemetry the project will be re-evaluated against:

- Jamil Ispahany et al. *SILRAD: Sysmon Dataset for Ransomware Analysis.* Zenodo,
  DOI <https://doi.org/10.5281/zenodo.17104902>
- *CSU-Ransomware-Data.* Charles Sturt University research output — 413,556 raw
  Sysmon events with engineered ransomware features.
- *Radar: a realistic dataset for advancing ransomware detection.* Zenodo,
  DOI <https://doi.org/10.5281/zenodo.14564541>

## AI-use note

AI coding assistance was used during implementation and drafting. The telemetry
design, comparative setup, debugging decisions, and final interpretation were directed
and verified by Farooq Syed.
