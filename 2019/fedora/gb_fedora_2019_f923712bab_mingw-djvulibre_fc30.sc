if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877033" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2019-15142", "CVE-2019-15143", "CVE-2019-15144", "CVE-2019-15145", "CVE-2019-18804" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-05-27 16:14:00 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2019-11-22 03:27:29 +0000 (Fri, 22 Nov 2019)" );
	script_name( "Fedora Update for mingw-djvulibre FEDORA-2019-f923712bab" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-f923712bab" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/QUEME45HVGTMDOYODAZYQOGWSZ2CEFWZ" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-djvulibre'
  package(s) announced via the FEDORA-2019-f923712bab advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows djvulibre library." );
	script_tag( name: "affected", value: "'mingw-djvulibre' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "mingw-djvulibre", rpm: "mingw-djvulibre~3.5.27~7.fc30", rls: "FC30" ) )){
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

