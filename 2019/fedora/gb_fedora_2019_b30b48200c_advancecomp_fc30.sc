if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876516" );
	script_version( "2021-09-01T12:01:34+0000" );
	script_cve_id( "CVE-2019-8383", "CVE-2019-8379" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 12:01:34 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-05-09 17:29:00 +0000 (Thu, 09 May 2019)" );
	script_tag( name: "creation_date", value: "2019-06-20 02:13:38 +0000 (Thu, 20 Jun 2019)" );
	script_name( "Fedora Update for advancecomp FEDORA-2019-b30b48200c" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-b30b48200c" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/J23C6QSTJMQ467KAI6QG54AE4MZRLPQV" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'advancecomp'
  package(s) announced via the FEDORA-2019-b30b48200c advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "AdvanceCOMP is a set of recompression utilities for .PNG, .MNG and .ZIP files.
The main features are :

  * Recompress ZIP, PNG and MNG files using the Deflate 7-Zip implementation.

  * Recompress MNG files using Delta and Move optimization.

This package contains:

  * advzip - Recompression and test utility for zip files

  * advpng - Recompression utility for png files

  * advmng - Recompression utility for mng files

  * advdef - Recompression utility for deflate streams in png, mng and gz files" );
	script_tag( name: "affected", value: "'advancecomp' package(s) on Fedora 30." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "FC30"){
	if(!isnull( res = isrpmvuln( pkg: "advancecomp", rpm: "advancecomp~2.1~11.fc30", rls: "FC30" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

