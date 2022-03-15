if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.818204" );
	script_version( "2021-09-20T14:50:00+0000" );
	script_cve_id( "CVE-2019-19785", "CVE-2019-19786", "CVE-2019-19787" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-20 14:50:00 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-04-03 03:15:00 +0000 (Sat, 03 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-04 03:04:33 +0000 (Sun, 04 Apr 2021)" );
	script_name( "Fedora: Security Advisory for atasm (FEDORA-2021-dc534847b2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-dc534847b2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/O6XQMOLMWHUDBN3PQJYGVULLNUBMGGJH" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'atasm'
  package(s) announced via the FEDORA-2021-dc534847b2 advisory.

  This VT has been deprecated and is therefore no longer functional." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "ATasm is a 6502 command-line cross-assembler that is compatible with the
original Mac/65 macro-assembler released by OSS software.  Code
development can now be performed using 'modern' editors and compiles
with lightning speed." );
	script_tag( name: "affected", value: "'atasm' package(s) on Fedora 32." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

