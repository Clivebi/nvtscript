if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873799" );
	script_version( "2021-09-13T11:01:38+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 11:01:38 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-23 08:16:06 +0100 (Thu, 23 Nov 2017)" );
	script_cve_id( "CVE-2015-9099", "CVE-2015-9100", "CVE-2017-11720", "CVE-2017-13712", "CVE-2017-15018", "CVE-2017-15019", "CVE-2017-15045", "CVE-2017-15046", "CVE-2017-9410", "CVE-2017-9411", "CVE-2017-9412", "CVE-2017-8419" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-31 01:29:00 +0000 (Thu, 31 Aug 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for lame FEDORA-2017-38830f1443" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'lame'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "lame on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-38830f1443" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/JY6563Y6FVVZHSHQNEB55R4KSYZGV2LR" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC25" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC25"){
	if(( res = isrpmvuln( pkg: "lame", rpm: "lame~3.100~1.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

