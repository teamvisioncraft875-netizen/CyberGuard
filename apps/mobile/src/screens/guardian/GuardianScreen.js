import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  SafeAreaView,
  TextInput,
  ActivityIndicator,
  Alert,
  RefreshControl,
  Platform
} from 'react-native';
import { COLORS } from '../../constants/colors';
import { useAuth } from '../../hooks/useAuth';
import { useSocket } from '../../hooks/useSocket';
import { guardianService } from '../../services/guardianService';
import { RiskBadge } from '../../components/RiskBadge';
import { CyberButton } from '../../components/CyberButton';

export function GuardianScreen({ navigation }) {
  const { user } = useAuth();
  const { latestIncident } = useSocket();

  // Primary data states
  const [links, setLinks] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);

  // Active top navigation tab: 'relationships' | 'alerts' | 'invite'
  const [activeTab, setActiveTab] = useState('relationships');
  // Sub-filter for relationships: 'all' | 'active' | 'pending'
  const [statusFilter, setStatusFilter] = useState('all');

  // Search & Invite state
  const [searchEmail, setSearchEmail] = useState('');
  const [searching, setSearching] = useState(false);
  const [foundUser, setFoundUser] = useState(null);
  const [searchError, setSearchError] = useState(null);
  const [inviteRoleMode, setInviteRoleMode] = useState('protect_dependent'); // 'protect_dependent' | 'protected_by'
  const [sendingInvite, setSendingInvite] = useState(false);
  const [inviteSuccess, setInviteSuccess] = useState('');

  // Per-item action loading map: { [linkId]: 'accept' | 'decline' | 'revoke' }
  const [actionLoading, setActionLoading] = useState({});

  // 1. Fetch Links and Alerts from Real Backend
  const fetchData = useCallback(async (isPullToRefresh = false) => {
    if (isPullToRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }
    setError(null);

    try {
      const [linksData, alertsData] = await Promise.all([
        guardianService.listLinks({ status: 'all' }),
        guardianService.getAlerts()
      ]);
      setLinks(linksData || []);
      setAlerts(alertsData || []);
    } catch (err) {
      console.warn('[GuardianScreen.fetchData error]', err.message);
      setError(err.message || 'Failed to load Guardian data. Please check connection.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // 2. Realtime Socket Incident Refresh
  // When an incident arrives over Socket.io, refresh alerts if relevant
  useEffect(() => {
    if (latestIncident?.id) {
      guardianService.getAlerts().then((updatedAlerts) => {
        setAlerts(updatedAlerts || []);
      }).catch(() => {});
    }
  }, [latestIncident]);

  // 3. Derived Real Metrics
  const metrics = useMemo(() => {
    const currentUserId = user?.id;
    let dependentsCount = 0;
    let guardiansCount = 0;
    let incomingPendingCount = 0;
    let outgoingPendingCount = 0;

    links.forEach((l) => {
      if (l.status === 'active') {
        if (l.guardian_user_id === currentUserId) dependentsCount++;
        if (l.dependent_user_id === currentUserId) guardiansCount++;
      } else if (l.status === 'pending') {
        if (l.dependent_user_id === currentUserId) incomingPendingCount++;
        if (l.guardian_user_id === currentUserId) outgoingPendingCount++;
      }
    });

    return {
      dependentsCount,
      guardiansCount,
      incomingPendingCount,
      outgoingPendingCount,
      totalPending: incomingPendingCount + outgoingPendingCount,
      alertsCount: alerts.length
    };
  }, [links, alerts, user?.id]);

  // Filtered links
  const filteredLinks = useMemo(() => {
    if (statusFilter === 'all') return links;
    return links.filter((l) => l.status === statusFilter);
  }, [links, statusFilter]);

  // Incoming pending requests directed to the current user
  const incomingPending = useMemo(() => {
    return links.filter((l) => l.status === 'pending' && l.dependent_user_id === user?.id);
  }, [links, user?.id]);

  // 4. Search User by Email
  const handleSearchUser = async () => {
    const cleanEmail = searchEmail.trim();
    if (!cleanEmail) {
      setSearchError('Please enter an email address to search.');
      return;
    }
    if (cleanEmail.toLowerCase() === user?.email?.toLowerCase()) {
      setSearchError('You cannot establish a guardian link with your own account.');
      return;
    }

    setSearching(true);
    setSearchError(null);
    setFoundUser(null);
    setInviteSuccess('');

    try {
      const res = await guardianService.searchUserByEmail(cleanEmail);
      const targetUser = res?.user || (Array.isArray(res?.users) ? res.users[0] : null) || (res?.id ? res : null);
      if (!targetUser || !targetUser.id) {
        setSearchError('No registered CyberGuard user found with this email.');
      } else if (targetUser.id === user?.id) {
        setSearchError('You cannot link your own account as a dependent.');
      } else {
        setFoundUser(targetUser);
      }
    } catch (err) {
      if (err.status === 404 || err.code === 'NOT_FOUND') {
        setSearchError('No registered user found with this email. The user must register first.');
      } else {
        setSearchError(err.message || 'Failed to search for user.');
      }
    } finally {
      setSearching(false);
    }
  };

  // 5. Send Link Invitation
  const handleSendInvite = async () => {
    if (!foundUser || !foundUser.id) {
      setSearchError('Please select a valid user first.');
      return;
    }

    setSendingInvite(true);
    setSearchError(null);

    const guardian_user_id = inviteRoleMode === 'protect_dependent' ? user.id : foundUser.id;
    const dependent_user_id = inviteRoleMode === 'protect_dependent' ? foundUser.id : user.id;

    try {
      await guardianService.createLink({
        guardian_user_id,
        dependent_user_id
      });
      setInviteSuccess(`Guardian invitation sent to ${foundUser.email}. Awaiting acceptance.`);
      setFoundUser(null);
      setSearchEmail('');
      await fetchData();
    } catch (err) {
      setSearchError(err.message || 'Failed to create guardian link.');
    } finally {
      setSendingInvite(false);
    }
  };

  // 6. Accept Link
  const handleAcceptLink = async (linkId) => {
    setActionLoading((prev) => ({ ...prev, [linkId]: 'accept' }));
    try {
      await guardianService.acceptLink(linkId);
      await fetchData();
    } catch (err) {
      Alert.alert('Action Failed', err.message || 'Failed to accept guardian link.');
    } finally {
      setActionLoading((prev) => ({ ...prev, [linkId]: null }));
    }
  };

  // 7. Decline Link
  const handleDeclineLink = async (linkId) => {
    setActionLoading((prev) => ({ ...prev, [linkId]: 'decline' }));
    try {
      await guardianService.declineLink(linkId);
      await fetchData();
    } catch (err) {
      Alert.alert('Action Failed', err.message || 'Failed to decline guardian link.');
    } finally {
      setActionLoading((prev) => ({ ...prev, [linkId]: null }));
    }
  };

  // 8. Revoke Link
  const handleRevokeLink = (linkId, otherEmail) => {
    Alert.alert(
      'Revoke Guardian Link?',
      `This will remove the current Guardian relationship with ${otherEmail || 'this user'}.`,
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Revoke',
          style: 'destructive',
          onPress: async () => {
            setActionLoading((prev) => ({ ...prev, [linkId]: 'revoke' }));
            try {
              await guardianService.revokeLink(linkId);
              await fetchData();
            } catch (err) {
              Alert.alert('Action Failed', err.message || 'Failed to revoke link.');
            } finally {
              setActionLoading((prev) => ({ ...prev, [linkId]: null }));
            }
          }
        }
      ]
    );
  };

  const formatTimestamp = (ts) => {
    if (!ts) return '';
    try {
      const d = new Date(ts);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch {
      return String(ts);
    }
  };

  return (
    <SafeAreaView style={styles.safeArea}>
      {/* Top Header */}
      <View style={styles.header}>
        <TouchableOpacity
          style={styles.backBtn}
          onPress={() => navigation.goBack()}
          accessibilityLabel="Back to Dashboard"
          accessibilityRole="button"
        >
          <Text style={styles.backBtnText}>← Dashboard</Text>
        </TouchableOpacity>
        <View style={styles.titleRow}>
          <Text style={styles.title}>Guardian Mode</Text>
          <View style={styles.modeBadge}>
            <Text style={styles.modeBadgeText}>FAMILY DEFENSE</Text>
          </View>
        </View>
        <Text style={styles.subtitle}>
          Shield family and dependents with real-time incident alerting
        </Text>
      </View>

      <ScrollView
        contentContainerStyle={styles.content}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={() => fetchData(true)}
            tintColor={COLORS.primary}
            colors={[COLORS.primary]}
          />
        }
      >
        {/* Error Banner */}
        {error ? (
          <View style={styles.errorBox} accessibilityRole="alert">
            <Text style={styles.errorText}>{error}</Text>
            <TouchableOpacity onPress={() => fetchData()} style={styles.retryBtn}>
              <Text style={styles.retryBtnText}>Retry</Text>
            </TouchableOpacity>
          </View>
        ) : null}

        {/* Real Metrics Banner */}
        <View style={styles.metricsGrid}>
          <View style={styles.metricCard}>
            <Text style={styles.metricValue}>{metrics.dependentsCount}</Text>
            <Text style={styles.metricLabel}>Protected</Text>
            <Text style={styles.metricSub}>Dependents</Text>
          </View>
          <View style={styles.metricCard}>
            <Text style={styles.metricValue}>{metrics.guardiansCount}</Text>
            <Text style={styles.metricLabel}>Guardians</Text>
            <Text style={styles.metricSub}>Protecting You</Text>
          </View>
          <View style={styles.metricCard}>
            <Text style={[styles.metricValue, metrics.totalPending > 0 && { color: COLORS.warning }]}>
              {metrics.totalPending}
            </Text>
            <Text style={styles.metricLabel}>Pending</Text>
            <Text style={styles.metricSub}>Requests</Text>
          </View>
          <View style={styles.metricCard}>
            <Text style={[styles.metricValue, metrics.alertsCount > 0 && { color: COLORS.critical }]}>
              {metrics.alertsCount}
            </Text>
            <Text style={styles.metricLabel}>Threat</Text>
            <Text style={styles.metricSub}>Alerts</Text>
          </View>
        </View>

        {/* Main Tabs */}
        <View style={styles.tabContainer}>
          <TouchableOpacity
            style={[styles.tabBtn, activeTab === 'relationships' && styles.tabBtnActive]}
            onPress={() => setActiveTab('relationships')}
            accessibilityRole="tab"
          >
            <Text style={[styles.tabText, activeTab === 'relationships' && styles.tabTextActive]}>
              Relationships ({links.length})
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.tabBtn, activeTab === 'alerts' && styles.tabBtnActive]}
            onPress={() => setActiveTab('alerts')}
            accessibilityRole="tab"
          >
            <Text style={[styles.tabText, activeTab === 'alerts' && styles.tabTextActive]}>
              Alerts ({alerts.length})
            </Text>
          </TouchableOpacity>
          <TouchableOpacity
            style={[styles.tabBtn, activeTab === 'invite' && styles.tabBtnActive]}
            onPress={() => setActiveTab('invite')}
            accessibilityRole="tab"
          >
            <Text style={[styles.tabText, activeTab === 'invite' && styles.tabTextActive]}>
              + Link User
            </Text>
          </TouchableOpacity>
        </View>

        {/* Loading Spinner */}
        {loading && !refreshing ? (
          <View style={styles.loadingBox}>
            <ActivityIndicator size="large" color={COLORS.primary} />
            <Text style={styles.loadingText}>Loading Guardian relationships...</Text>
          </View>
        ) : null}

        {/* -------------------- TAB 1: RELATIONSHIPS -------------------- */}
        {!loading && activeTab === 'relationships' && (
          <View>
            {/* Actionable Incoming Requests Notice */}
            {incomingPending.length > 0 && (
              <View style={styles.actionNoticeCard}>
                <Text style={styles.actionNoticeTitle}>⚠️ INCOMING INVITATIONS PENDING</Text>
                <Text style={styles.actionNoticeDesc}>
                  You have {incomingPending.length} guardian request{incomingPending.length === 1 ? '' : 's'} awaiting your approval.
                </Text>
              </View>
            )}

            {/* Sub Filter */}
            <View style={styles.subFilterRow}>
              {['all', 'active', 'pending'].map((filter) => (
                <TouchableOpacity
                  key={filter}
                  style={[styles.filterChip, statusFilter === filter && styles.filterChipActive]}
                  onPress={() => setStatusFilter(filter)}
                >
                  <Text style={[styles.filterChipText, statusFilter === filter && styles.filterChipTextActive]}>
                    {filter.toUpperCase()}
                  </Text>
                </TouchableOpacity>
              ))}
            </View>

            {/* Links List */}
            {filteredLinks.length === 0 ? (
              <View style={styles.emptyCard}>
                <Text style={styles.emptyIcon}>🛡️</Text>
                <Text style={styles.emptyTitle}>
                  {statusFilter === 'all'
                    ? 'No Guardian relationships yet.'
                    : `No ${statusFilter} Guardian links.`}
                </Text>
                <Text style={styles.emptySubtitle}>
                  Link a family member or dependent to monitor high-risk cyber incidents autonomously.
                </Text>
                <TouchableOpacity
                  style={styles.emptyCtaBtn}
                  onPress={() => setActiveTab('invite')}
                >
                  <Text style={styles.emptyCtaText}>+ Invite Guardian or Dependent</Text>
                </TouchableOpacity>
              </View>
            ) : (
              filteredLinks.map((link) => {
                const isUserGuardian = link.guardian_user_id === user?.id;
                const otherEmail = isUserGuardian ? link.dependent_email : link.guardian_email;
                const relationshipRole = isUserGuardian ? 'Protected Dependent' : 'Protecting Guardian';
                const isPending = link.status === 'pending';
                const isIncomingToMe = isPending && !isUserGuardian;
                const isActionLoading = actionLoading[link.id || link.link_id];

                return (
                  <View key={link.id || link.link_id} style={styles.linkCard}>
                    <View style={styles.linkHeader}>
                      <View style={styles.linkUserCol}>
                        <Text style={styles.linkRoleLabel}>
                          {isUserGuardian ? '🛡️ DEPENDENT' : '👤 GUARDIAN'}
                        </Text>
                        <Text style={styles.linkEmail} numberOfLines={1}>
                          {otherEmail || 'User'}
                        </Text>
                      </View>
                      <View
                        style={[
                          styles.statusBadge,
                          link.status === 'active' && styles.statusBadgeActive,
                          link.status === 'pending' && styles.statusBadgePending,
                          link.status === 'revoked' && styles.statusBadgeRevoked
                        ]}
                      >
                        <Text
                          style={[
                            styles.statusBadgeText,
                            link.status === 'active' && styles.statusTextActive,
                            link.status === 'pending' && styles.statusTextPending,
                            link.status === 'revoked' && styles.statusTextRevoked
                          ]}
                        >
                          {(link.status || 'unknown').toUpperCase()}
                        </Text>
                      </View>
                    </View>

                    <Text style={styles.linkMeta}>
                      Role: {relationshipRole} • Linked: {formatTimestamp(link.created_at)}
                    </Text>

                    {/* Actions for Incoming Requests */}
                    {isIncomingToMe && (
                      <View style={styles.incomingActionRow}>
                        <TouchableOpacity
                          style={[styles.acceptBtn, isActionLoading && styles.btnDisabled]}
                          onPress={() => handleAcceptLink(link.id || link.link_id)}
                          disabled={Boolean(isActionLoading)}
                          accessibilityLabel="Accept Guardian Request"
                        >
                          {isActionLoading === 'accept' ? (
                            <ActivityIndicator size="small" color="#0a0f1d" />
                          ) : (
                            <Text style={styles.acceptBtnText}>✓ Accept Request</Text>
                          )}
                        </TouchableOpacity>
                        <TouchableOpacity
                          style={[styles.declineBtn, isActionLoading && styles.btnDisabled]}
                          onPress={() => handleDeclineLink(link.id || link.link_id)}
                          disabled={Boolean(isActionLoading)}
                          accessibilityLabel="Decline Guardian Request"
                        >
                          {isActionLoading === 'decline' ? (
                            <ActivityIndicator size="small" color="#fff" />
                          ) : (
                            <Text style={styles.declineBtnText}>✕ Decline</Text>
                          )}
                        </TouchableOpacity>
                      </View>
                    )}

                    {/* Revoke Action for Active or Outgoing Pending */}
                    {!isIncomingToMe && link.status !== 'revoked' && (
                      <View style={styles.revokeActionRow}>
                        <TouchableOpacity
                          style={[styles.revokeBtn, isActionLoading && styles.btnDisabled]}
                          onPress={() => handleRevokeLink(link.id || link.link_id, otherEmail)}
                          disabled={Boolean(isActionLoading)}
                          accessibilityLabel="Revoke Guardian Link"
                        >
                          {isActionLoading === 'revoke' ? (
                            <ActivityIndicator size="small" color={COLORS.critical} />
                          ) : (
                            <Text style={styles.revokeBtnText}>
                              {isPending ? 'Cancel Invitation' : 'Revoke Link'}
                            </Text>
                          )}
                        </TouchableOpacity>
                      </View>
                    )}
                  </View>
                );
              })
            )}
          </View>
        )}

        {/* -------------------- TAB 2: ALERTS -------------------- */}
        {!loading && activeTab === 'alerts' && (
          <View>
            {alerts.length === 0 ? (
              <View style={styles.emptyCard}>
                <Text style={styles.emptyIcon}>✅</Text>
                <Text style={styles.emptyTitle}>No Guardian alerts.</Text>
                <Text style={styles.emptySubtitle}>
                  All protected dependents currently report normal security status with zero critical threats.
                </Text>
              </View>
            ) : (
              alerts.map((alert) => (
                <View key={alert.alert_id} style={styles.alertCard}>
                  <View style={styles.alertHeader}>
                    <View style={styles.alertTitleCol}>
                      <Text style={styles.alertDependentName}>
                        👤 {alert.dependent_name || 'Protected Dependent'}
                      </Text>
                      <Text style={styles.alertThreatType}>
                        {alert.threat_type ? alert.threat_type.replace(/_/g, ' ').toUpperCase() : 'SECURITY INCIDENT'}
                      </Text>
                    </View>
                    <RiskBadge level={alert.risk_level || 'High'} size="small" />
                  </View>

                  <Text style={styles.alertExplanation}>
                    {alert.explanation || 'High-risk security threat detected on dependent account.'}
                  </Text>

                  {alert.recommended_action ? (
                    <View style={styles.actionBox}>
                      <Text style={styles.actionLabel}>RECOMMENDED ACTION</Text>
                      <Text style={styles.actionText}>{alert.recommended_action}</Text>
                    </View>
                  ) : null}

                  <Text style={styles.alertTimestamp}>
                    Reported: {formatTimestamp(alert.timestamp)}
                  </Text>
                </View>
              ))
            )}
          </View>
        )}

        {/* -------------------- TAB 3: INVITE / LINK USER -------------------- */}
        {!loading && activeTab === 'invite' && (
          <View style={styles.inviteContainer}>
            <View style={styles.card}>
              <Text style={styles.cardHeading}>SEARCH USER BY EMAIL</Text>
              <Text style={styles.cardSubheading}>
                Enter the registered email of the user you want to link.
              </Text>

              {searchError ? (
                <View style={styles.inlineErrorBox}>
                  <Text style={styles.inlineErrorText}>{searchError}</Text>
                </View>
              ) : null}

              {inviteSuccess ? (
                <View style={styles.inlineSuccessBox}>
                  <Text style={styles.inlineSuccessText}>✓ {inviteSuccess}</Text>
                </View>
              ) : null}

              <View style={styles.searchRow}>
                <TextInput
                  style={styles.searchInput}
                  placeholder="e.g. family.member@domain.com"
                  placeholderTextColor={COLORS.textMuted}
                  value={searchEmail}
                  onChangeText={(val) => {
                    setSearchEmail(val);
                    if (searchError) setSearchError(null);
                    if (inviteSuccess) setInviteSuccess('');
                  }}
                  autoCapitalize="none"
                  keyboardType="email-address"
                  autoCorrect={false}
                  editable={!searching && !sendingInvite}
                />
                <TouchableOpacity
                  style={[styles.searchBtn, (!searchEmail.trim() || searching) && styles.btnDisabled]}
                  onPress={handleSearchUser}
                  disabled={!searchEmail.trim() || searching}
                >
                  {searching ? (
                    <ActivityIndicator size="small" color="#0a0f1d" />
                  ) : (
                    <Text style={styles.searchBtnText}>Search</Text>
                  )}
                </TouchableOpacity>
              </View>

              {/* Found User Profile & Role Selector */}
              {foundUser && (
                <View style={styles.foundUserCard}>
                  <Text style={styles.foundUserTitle}>USER FOUND</Text>
                  <Text style={styles.foundUserEmail}>{foundUser.email}</Text>
                  <Text style={styles.foundUserRole}>Role: {foundUser.role || 'user'}</Text>

                  <Text style={[styles.cardHeading, { marginTop: 14, marginBottom: 8 }]}>
                    SELECT RELATIONSHIP INTENT
                  </Text>

                  <TouchableOpacity
                    style={[
                      styles.roleOption,
                      inviteRoleMode === 'protect_dependent' && styles.roleOptionActive
                    ]}
                    onPress={() => setInviteRoleMode('protect_dependent')}
                  >
                    <Text style={styles.roleOptionIcon}>🛡️</Text>
                    <View style={styles.roleOptionTextCol}>
                      <Text style={styles.roleOptionTitle}>Protect as Dependent</Text>
                      <Text style={styles.roleOptionDesc}>
                        You will receive high-severity threat alerts for this user.
                      </Text>
                    </View>
                  </TouchableOpacity>

                  <TouchableOpacity
                    style={[
                      styles.roleOption,
                      inviteRoleMode === 'protected_by' && styles.roleOptionActive,
                      { marginTop: 8 }
                    ]}
                    onPress={() => setInviteRoleMode('protected_by')}
                  >
                    <Text style={styles.roleOptionIcon}>👤</Text>
                    <View style={styles.roleOptionTextCol}>
                      <Text style={styles.roleOptionTitle}>Request as My Guardian</Text>
                      <Text style={styles.roleOptionDesc}>
                        This user will be notified if your account encounters critical threats.
                      </Text>
                    </View>
                  </TouchableOpacity>

                  <CyberButton
                    title={sendingInvite ? 'Sending Invitation...' : 'Send Guardian Invitation'}
                    onPress={handleSendInvite}
                    loading={sendingInvite}
                    disabled={sendingInvite}
                    style={{ marginTop: 16 }}
                  />
                </View>
              )}
            </View>

            {/* Privacy / Safety Explainer */}
            <View style={styles.privacyCard}>
              <Text style={styles.privacyHeading}>🔒 GUARDIAN PRIVACY PROTOCOL</Text>
              <Text style={styles.privacyText}>
                • Guardians ONLY receive alerts for High and Critical security incidents.
                {'\n'}• Passwords, personal messages, and sensitive content are never revealed.
                {'\n'}• Either party may revoke the link at any time without admin intervention.
              </Text>
            </View>
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.background
  },
  header: {
    paddingHorizontal: 16,
    paddingTop: 8,
    paddingBottom: 14,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.border
  },
  backBtn: {
    marginBottom: 6
  },
  backBtnText: {
    color: COLORS.primary,
    fontSize: 13,
    fontWeight: '700'
  },
  titleRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8
  },
  title: {
    color: COLORS.textPrimary,
    fontSize: 22,
    fontWeight: '800'
  },
  modeBadge: {
    backgroundColor: 'rgba(0, 240, 255, 0.12)',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 6,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)'
  },
  modeBadgeText: {
    color: COLORS.primary,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  subtitle: {
    color: COLORS.textMuted,
    fontSize: 13,
    marginTop: 2
  },
  content: {
    padding: 16,
    paddingBottom: 40
  },
  errorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.4)',
    borderRadius: 10,
    padding: 12,
    marginBottom: 16,
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center'
  },
  errorText: {
    color: COLORS.critical,
    fontSize: 13,
    flex: 1,
    fontWeight: '600'
  },
  retryBtn: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    backgroundColor: COLORS.critical,
    borderRadius: 6,
    marginLeft: 10
  },
  retryBtnText: {
    color: '#fff',
    fontSize: 12,
    fontWeight: '700'
  },
  metricsGrid: {
    flexDirection: 'row',
    gap: 8,
    marginBottom: 16
  },
  metricCard: {
    flex: 1,
    backgroundColor: COLORS.card,
    borderRadius: 12,
    padding: 10,
    borderWidth: 1,
    borderColor: COLORS.border,
    alignItems: 'center'
  },
  metricValue: {
    color: COLORS.primary,
    fontSize: 18,
    fontWeight: '800'
  },
  metricLabel: {
    color: COLORS.textPrimary,
    fontSize: 11,
    fontWeight: '700',
    marginTop: 2
  },
  metricSub: {
    color: COLORS.textMuted,
    fontSize: 9,
    textAlign: 'center'
  },
  tabContainer: {
    flexDirection: 'row',
    backgroundColor: COLORS.surface,
    borderRadius: 10,
    padding: 3,
    marginBottom: 16
  },
  tabBtn: {
    flex: 1,
    paddingVertical: 9,
    alignItems: 'center',
    borderRadius: 8
  },
  tabBtnActive: {
    backgroundColor: COLORS.card,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)'
  },
  tabText: {
    color: COLORS.textMuted,
    fontSize: 12,
    fontWeight: '700'
  },
  tabTextActive: {
    color: COLORS.primary
  },
  loadingBox: {
    padding: 40,
    alignItems: 'center'
  },
  loadingText: {
    color: COLORS.textMuted,
    fontSize: 13,
    marginTop: 12
  },
  actionNoticeCard: {
    backgroundColor: 'rgba(245, 158, 11, 0.1)',
    borderRadius: 12,
    borderWidth: 1,
    borderColor: 'rgba(245, 158, 11, 0.35)',
    padding: 14,
    marginBottom: 12
  },
  actionNoticeTitle: {
    color: COLORS.warning,
    fontSize: 12,
    fontWeight: '800',
    letterSpacing: 0.5,
    marginBottom: 2
  },
  actionNoticeDesc: {
    color: COLORS.textPrimary,
    fontSize: 12
  },
  subFilterRow: {
    flexDirection: 'row',
    gap: 8,
    marginBottom: 12
  },
  filterChip: {
    paddingHorizontal: 12,
    paddingVertical: 5,
    borderRadius: 8,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  filterChipActive: {
    backgroundColor: 'rgba(0, 240, 255, 0.15)',
    borderColor: COLORS.primary
  },
  filterChipText: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '700'
  },
  filterChipTextActive: {
    color: COLORS.primary
  },
  emptyCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 30,
    alignItems: 'center',
    marginTop: 8
  },
  emptyIcon: {
    fontSize: 36,
    marginBottom: 10
  },
  emptyTitle: {
    color: COLORS.textPrimary,
    fontSize: 16,
    fontWeight: '700',
    marginBottom: 6,
    textAlign: 'center'
  },
  emptySubtitle: {
    color: COLORS.textMuted,
    fontSize: 12,
    textAlign: 'center',
    lineHeight: 18,
    marginBottom: 16
  },
  emptyCtaBtn: {
    backgroundColor: 'rgba(0, 240, 255, 0.12)',
    borderWidth: 1,
    borderColor: COLORS.primary,
    borderRadius: 8,
    paddingVertical: 10,
    paddingHorizontal: 16
  },
  emptyCtaText: {
    color: COLORS.primary,
    fontSize: 12,
    fontWeight: '700'
  },
  linkCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 16,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 12
  },
  linkHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 8
  },
  linkUserCol: {
    flex: 1,
    marginRight: 10
  },
  linkRoleLabel: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 0.5,
    marginBottom: 2
  },
  linkEmail: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '700'
  },
  linkMeta: {
    color: COLORS.textMuted,
    fontSize: 11,
    marginBottom: 10
  },
  statusBadge: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
    borderWidth: 1
  },
  statusBadgeActive: {
    backgroundColor: 'rgba(16, 185, 129, 0.12)',
    borderColor: 'rgba(16, 185, 129, 0.4)'
  },
  statusBadgePending: {
    backgroundColor: 'rgba(245, 158, 11, 0.12)',
    borderColor: 'rgba(245, 158, 11, 0.4)'
  },
  statusBadgeRevoked: {
    backgroundColor: 'rgba(100, 116, 139, 0.12)',
    borderColor: 'rgba(100, 116, 139, 0.4)'
  },
  statusBadgeText: {
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  statusTextActive: { color: COLORS.safe },
  statusTextPending: { color: COLORS.warning },
  statusTextRevoked: { color: COLORS.textMuted },
  incomingActionRow: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 6
  },
  acceptBtn: {
    flex: 1,
    backgroundColor: COLORS.safe,
    paddingVertical: 9,
    borderRadius: 8,
    alignItems: 'center',
    justifyContent: 'center'
  },
  acceptBtnText: {
    color: '#0a0f1d',
    fontSize: 12,
    fontWeight: '800'
  },
  declineBtn: {
    flex: 1,
    backgroundColor: 'rgba(239, 68, 68, 0.2)',
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.5)',
    paddingVertical: 9,
    borderRadius: 8,
    alignItems: 'center',
    justifyContent: 'center'
  },
  declineBtnText: {
    color: COLORS.critical,
    fontSize: 12,
    fontWeight: '700'
  },
  revokeActionRow: {
    alignItems: 'flex-end',
    marginTop: 4
  },
  revokeBtn: {
    paddingVertical: 4,
    paddingHorizontal: 8
  },
  revokeBtnText: {
    color: COLORS.critical,
    fontSize: 11,
    fontWeight: '700'
  },
  btnDisabled: {
    opacity: 0.5
  },
  alertCard: {
    backgroundColor: COLORS.card,
    borderRadius: 14,
    padding: 16,
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.35)',
    borderLeftWidth: 4,
    borderLeftColor: COLORS.critical,
    marginBottom: 12
  },
  alertHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 8
  },
  alertTitleCol: {
    flex: 1,
    marginRight: 10
  },
  alertDependentName: {
    color: COLORS.textPrimary,
    fontSize: 14,
    fontWeight: '700',
    marginBottom: 2
  },
  alertThreatType: {
    color: COLORS.critical,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 0.5
  },
  alertExplanation: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 17,
    marginBottom: 10
  },
  actionBox: {
    backgroundColor: COLORS.surface,
    borderRadius: 8,
    padding: 10,
    marginBottom: 8,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  actionLabel: {
    color: COLORS.primary,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 0.5,
    marginBottom: 3
  },
  actionText: {
    color: COLORS.textPrimary,
    fontSize: 11,
    lineHeight: 15
  },
  alertTimestamp: {
    color: COLORS.textMuted,
    fontSize: 10
  },
  inviteContainer: {
    marginTop: 4
  },
  card: {
    backgroundColor: COLORS.card,
    borderRadius: 16,
    padding: 16,
    borderWidth: 1,
    borderColor: COLORS.border,
    marginBottom: 16
  },
  cardHeading: {
    color: COLORS.textMuted,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1
  },
  cardSubheading: {
    color: COLORS.textSecondary,
    fontSize: 12,
    marginTop: 2,
    marginBottom: 12
  },
  searchRow: {
    flexDirection: 'row',
    gap: 8
  },
  searchInput: {
    flex: 1,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border,
    borderRadius: 10,
    paddingHorizontal: 12,
    paddingVertical: 10,
    color: COLORS.textPrimary,
    fontSize: 13
  },
  searchBtn: {
    backgroundColor: COLORS.primary,
    borderRadius: 10,
    paddingHorizontal: 16,
    justifyContent: 'center',
    alignItems: 'center'
  },
  searchBtnText: {
    color: '#0a0f1d',
    fontSize: 13,
    fontWeight: '800'
  },
  inlineErrorBox: {
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    borderRadius: 8,
    padding: 10,
    marginBottom: 10,
    borderWidth: 1,
    borderColor: 'rgba(239, 68, 68, 0.3)'
  },
  inlineErrorText: {
    color: COLORS.critical,
    fontSize: 12,
    fontWeight: '600'
  },
  inlineSuccessBox: {
    backgroundColor: 'rgba(16, 185, 129, 0.15)',
    borderRadius: 8,
    padding: 10,
    marginBottom: 10,
    borderWidth: 1,
    borderColor: 'rgba(16, 185, 129, 0.3)'
  },
  inlineSuccessText: {
    color: COLORS.safe,
    fontSize: 12,
    fontWeight: '700'
  },
  foundUserCard: {
    backgroundColor: COLORS.surface,
    borderRadius: 12,
    padding: 14,
    marginTop: 14,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.3)'
  },
  foundUserTitle: {
    color: COLORS.primary,
    fontSize: 10,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 2
  },
  foundUserEmail: {
    color: COLORS.textPrimary,
    fontSize: 15,
    fontWeight: '700'
  },
  foundUserRole: {
    color: COLORS.textMuted,
    fontSize: 11
  },
  roleOption: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: COLORS.card,
    borderRadius: 10,
    padding: 12,
    borderWidth: 1,
    borderColor: COLORS.border
  },
  roleOptionActive: {
    borderColor: COLORS.primary,
    backgroundColor: 'rgba(0, 240, 255, 0.08)'
  },
  roleOptionIcon: {
    fontSize: 20,
    marginRight: 10
  },
  roleOptionTextCol: {
    flex: 1
  },
  roleOptionTitle: {
    color: COLORS.textPrimary,
    fontSize: 13,
    fontWeight: '700'
  },
  roleOptionDesc: {
    color: COLORS.textMuted,
    fontSize: 11,
    marginTop: 2
  },
  privacyCard: {
    backgroundColor: 'rgba(0, 240, 255, 0.04)',
    borderRadius: 12,
    padding: 14,
    borderWidth: 1,
    borderColor: 'rgba(0, 240, 255, 0.15)'
  },
  privacyHeading: {
    color: COLORS.primary,
    fontSize: 11,
    fontWeight: '800',
    letterSpacing: 1,
    marginBottom: 6
  },
  privacyText: {
    color: COLORS.textSecondary,
    fontSize: 12,
    lineHeight: 18
  }
});
