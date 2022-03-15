if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807742" );
	script_version( "$Revision: 14223 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 14:49:35 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-11 12:47:18 +0530 (Mon, 11 Apr 2016)" );
	script_cve_id( "CVE-2015-1120", "CVE-2015-1076", "CVE-2015-1071", "CVE-2015-1081", "CVE-2015-1122", "CVE-2015-1155", "CVE-2014-1748", "CVE-2015-3752", "CVE-2015-5809", "CVE-2015-5928", "CVE-2015-3749", "CVE-2015-3659", "CVE-2015-3748", "CVE-2015-3743", "CVE-2015-3731", "CVE-2015-3745", "CVE-2015-5822", "CVE-2015-3658", "CVE-2015-3741", "CVE-2015-3727", "CVE-2015-5801", "CVE-2015-5788", "CVE-2015-3747", "CVE-2015-5794", "CVE-2015-1127", "CVE-2015-1153", "CVE-2015-1083" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for webkitgtk FEDORA-2016-9" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkitgtk'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "webkitgtk on Fedora 22" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2016-9" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/pipermail/package-announce/2016-March/180485.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC22" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC22"){
	if(( res = isrpmvuln( pkg: "webkitgtk", rpm: "webkitgtk~2.4.10~1.fc22", rls: "FC22" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

