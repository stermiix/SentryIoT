// O design system do SentryIoT dentro do app: componentes, vocabulário, formatos e imagens da marca.
// As telas importam daqui, e não dos arquivos de `components/`. As regras de uso estão no README.md
// desta pasta e em COMPONENTES.md.
import "./tokens.css";
import "./styles.css";

export { Icon, Kbd, type IconName } from "./components/Icon";
export { Logo, GlassBackdrop } from "./components/Brand";
export { Button, IconButton } from "./components/Button";
export { CategoryBadge, StatusBadge, RiskBadge, AgentBadge, ChannelTag, TargetLabel } from "./components/Badges";
export { Panel, PageHeader, ModeIndicator, Segmented, Tabs, Sidebar, AppShell, type NavSection, type NavItem, type SegmentedOption } from "./components/Layout";
export { TextField, Select } from "./components/Fields";
export { MetricCard, AggregationFunnel, ConfidenceMeter, ClassifierVerdict, IncidentQueue, FeatureTable, AddressList } from "./components/Data";
export { EventTimeline, ProposalCard, VoiceQuote } from "./components/Agents";
export { ReplayControl, type ReplayMark } from "./components/Replay";
export { Alert, EmptyState, Skeleton, Tooltip, ConfirmDialog } from "./components/Feedback";
export { AreaChart, CategoryBars, ConfusionMatrix, type ChartSeries } from "./components/Charts";
export { ChatMessage, PromptBox, ModelSelect, ProviderBar } from "./components/Chat";
export { ReportCover, ReportPage, ReportSection, ReportFacts } from "./components/Report";
export * from "./components/vocab";
export * from "./components/util";
export type * from "./components/modelos";
export { ASSETS } from "./assets";
