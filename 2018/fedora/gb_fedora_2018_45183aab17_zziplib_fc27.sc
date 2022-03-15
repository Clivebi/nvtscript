if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875060" );
	script_version( "2021-06-08T02:00:22+0000" );
	script_tag( name: "last_modification", value: "2021-06-08 02:00:22 +0000 (Tue, 08 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-09-14 07:47:34 +0200 (Fri, 14 Sep 2018)" );
	script_cve_id( "CVE-2018-6869", "CVE-2018-6484", "CVE-2018-6541", "CVE-2018-7727", "CVE-2018-6381", "CVE-2018-7725" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-06-28 15:15:00 +0000 (Sun, 28 Jun 2020)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for zziplib FEDORA-2018-45183aab17" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'zziplib'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "affected", value: "zziplib on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "FEDORA", value: "2018-45183aab17" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MKVLTCQZTM4IO2OP63CRKPLX6NQKLQ2O" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC27"){
	if(( res = isrpmvuln( pkg: "zziplib", rpm: "zziplib~0.13.69~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

