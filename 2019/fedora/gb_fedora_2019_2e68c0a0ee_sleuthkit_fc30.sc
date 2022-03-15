if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.876734" );
	script_version( "2021-09-01T09:01:32+0000" );
	script_cve_id( "CVE-2019-1010065" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 09:01:32 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-08-30 09:15:00 +0000 (Fri, 30 Aug 2019)" );
	script_tag( name: "creation_date", value: "2019-08-31 02:19:35 +0000 (Sat, 31 Aug 2019)" );
	script_name( "Fedora Update for sleuthkit FEDORA-2019-2e68c0a0ee" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC30" );
	script_xref( name: "FEDORA", value: "2019-2e68c0a0ee" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/FGWCQIZKTDCJO4YGL5LGPYFNOVU7SJRX" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sleuthkit'
  package(s) announced via the FEDORA-2019-2e68c0a0ee advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Sleuth Kit (TSK) is a collection of UNIX-based command line tools that
allow you to investigate a computer. The current focus of the tools is the
file and volume systems and TSK supports FAT, Ext2/3, NTFS, UFS,
and ISO 9660 file systems" );
	script_tag( name: "affected", value: "'sleuthkit' package(s) on Fedora 30." );
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
	if(!isnull( res = isrpmvuln( pkg: "sleuthkit", rpm: "sleuthkit~4.6.7~1.fc30", rls: "FC30" ) )){
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
