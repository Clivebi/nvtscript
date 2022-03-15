if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0984.1" );
	script_cve_id( "CVE-2015-3627", "CVE-2015-3629", "CVE-2015-3630", "CVE-2015-3631" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-08-13 21:47:00 +0000 (Mon, 13 Aug 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0984-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0984-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150984-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'docker' package(s) announced via the SUSE-SU-2015:0984-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Linux container runtime environment Docker was updated to version 1.6.2 to fix several security and non-security issues.
- Security:
 - Fix read/write /proc paths. (CVE-2015-3630)
 - Prohibit VOLUME /proc and VOLUME /. (CVE-2015-3631)
 - Fix opening of file-descriptor 1. (CVE-2015-3627)
 - Fix symlink traversal on container respawn allowing local privilege
 escalation. (CVE-2015-3629)
- Runtime:
 - Update Apparmor policy to not allow mounts." );
	script_tag( name: "affected", value: "'docker' package(s) on SUSE Linux Enterprise Server 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "docker", rpm: "docker~1.6.2~31.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-debuginfo", rpm: "docker-debuginfo~1.6.2~31.2", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "docker-debugsource", rpm: "docker-debugsource~1.6.2~31.2", rls: "SLES12.0" ) )){
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

