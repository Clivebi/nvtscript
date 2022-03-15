if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.852590" );
	script_version( "2021-09-07T09:01:33+0000" );
	script_cve_id( "CVE-2019-9928" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-07 09:01:33 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-06-28 02:00:47 +0000 (Fri, 28 Jun 2019)" );
	script_name( "openSUSE: Security Advisory for gstreamer-0_10-plugins-base (openSUSE-SU-2019:1638-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap42\\.3" );
	script_xref( name: "openSUSE-SU", value: "2019:1638-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/opensuse-security-announce/2019-06/msg00082.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gstreamer-0_10-plugins-base'
  package(s) announced via the openSUSE-SU-2019:1638-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for gstreamer-0_10-plugins-base fixes the following issues:

  Security issue fixed:

  - CVE-2019-9928: Fixed a heap-based overflow in the rtsp connection parser
  (bsc#1133375).

  This update was imported from the SUSE:SLE-12-SP2:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1638=1" );
	script_tag( name: "affected", value: "'gstreamer-0_10-plugins-base' package(s) on openSUSE Leap 42.3." );
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
if(release == "openSUSELeap42.3"){
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugin-gnomevfs", rpm: "gstreamer-0_10-plugin-gnomevfs~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugin-gnomevfs-debuginfo", rpm: "gstreamer-0_10-plugin-gnomevfs-debuginfo~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-base", rpm: "gstreamer-0_10-plugins-base~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-base-debuginfo", rpm: "gstreamer-0_10-plugins-base-debuginfo~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-base-debugsource", rpm: "gstreamer-0_10-plugins-base-debugsource~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-base-devel", rpm: "gstreamer-0_10-plugins-base-devel~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-base-doc", rpm: "gstreamer-0_10-plugins-base-doc~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-0_10-0", rpm: "libgstapp-0_10-0~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-0_10-0-debuginfo", rpm: "libgstapp-0_10-0-debuginfo~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstinterfaces-0_10-0", rpm: "libgstinterfaces-0_10-0~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstinterfaces-0_10-0-debuginfo", rpm: "libgstinterfaces-0_10-0-debuginfo~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstApp-0_10", rpm: "typelib-1_0-GstApp-0_10~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-GstInterfaces-0_10", rpm: "typelib-1_0-GstInterfaces-0_10~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-base-lang", rpm: "gstreamer-0_10-plugins-base-lang~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-base-32bit", rpm: "gstreamer-0_10-plugins-base-32bit~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-0_10-plugins-base-debuginfo-32bit", rpm: "gstreamer-0_10-plugins-base-debuginfo-32bit~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-0_10-0-32bit", rpm: "libgstapp-0_10-0-32bit~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-0_10-0-debuginfo-32bit", rpm: "libgstapp-0_10-0-debuginfo-32bit~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstinterfaces-0_10-0-32bit", rpm: "libgstinterfaces-0_10-0-32bit~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstinterfaces-0_10-0-debuginfo-32bit", rpm: "libgstinterfaces-0_10-0-debuginfo-32bit~0.10.36~18.3.1", rls: "openSUSELeap42.3" ) )){
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

