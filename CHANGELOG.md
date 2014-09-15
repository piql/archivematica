dev (1.4.0)
===========

* Remove unused Elasticsearch backup code (#8076)
* Improve performance of indexing AIP by saving uncompressed METS (#7424)
* Index MODS identifiers in Elasticsearch (#7424)
* Track file events in transfer METS using amdSecs (#7714)
* Add a new "processed structMap" which captures the transfer's final state (#7714)
* Use the Storage Service, not Elasticsearch, to look up file metadata in SIP arrange (#7714)
* Improve Dublin Core namespacing for metadata generated from metadata.csv and from template (#8007)
* Display additional metadata (number of files, size) from the storage service (#7853)
* Accession IDs associate with Transfers again (#7442)