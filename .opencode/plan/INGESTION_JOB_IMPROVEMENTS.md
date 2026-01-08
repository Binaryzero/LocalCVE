# Ingestion Job Management Enhancement Plan

## Current Issues
1. **No job cancellation**: Once a job starts, there's no way to stop it
2. **Limited reporting**: Jobs only show basic info without detailed progress
3. **No change tracking**: Jobs don't show what CVEs were added/updated
4. **No management controls**: Cannot pause, cancel, or prioritize jobs
5. **Poor visibility**: No real-time progress updates or detailed status

## Proposed Solutions

### 1. Enhanced Job Database Schema
Add new fields to track job progress and changes:
- `progress_percent` - Real-time progress indicator (0-100)
- `items_added` - Count of new CVEs added
- `items_updated` - Count of existing CVEs updated
- `items_unchanged` - Count of unchanged CVEs
- `current_file` - Currently processing file path
- `cancel_requested` - Flag to signal job cancellation
- `priority` - Job priority level (LOW, NORMAL, HIGH)

### 2. Job Control API Endpoints
- `POST /api/jobs/:id/cancel` - Request job cancellation
- `POST /api/jobs/:id/pause` - Pause job execution
- `POST /api/jobs/:id/resume` - Resume paused job
- `PUT /api/jobs/:id/priority` - Change job priority

### 3. Enhanced Job Status Reporting
- Real-time progress updates with percentage completion
- Detailed change tracking (added/updated/unchanged counts)
- Current file being processed
- Estimated time remaining
- Memory usage statistics

### 4. Job Management UI Improvements
- Cancel/Pause/Resume buttons for active jobs
- Job priority controls
- Detailed progress modal with file-by-file tracking
- Change summary visualization (new vs updated CVEs)
- Export job logs functionality

### 5. Backend Implementation Changes

#### A. Database Schema Updates
```sql
ALTER TABLE job_runs ADD COLUMN progress_percent INTEGER DEFAULT 0;
ALTER TABLE job_runs ADD COLUMN items_added INTEGER DEFAULT 0;
ALTER TABLE job_runs ADD COLUMN items_updated INTEGER DEFAULT 0;
ALTER TABLE job_runs ADD COLUMN items_unchanged INTEGER DEFAULT 0;
ALTER TABLE job_runs ADD COLUMN current_file TEXT;
ALTER TABLE job_runs ADD COLUMN cancel_requested INTEGER DEFAULT 0;
ALTER TABLE job_runs ADD COLUMN priority TEXT DEFAULT 'NORMAL';
```

#### B. Ingestion Process Enhancements
1. **Cancellation Checkpoints**: Add periodic checks for cancel_requested flag
2. **Progress Tracking**: Update progress_percent and current_file during processing
3. **Change Tracking**: Count added/updated/unchanged items separately
4. **Pause/Resume Logic**: Implement state persistence for pausing jobs

#### C. New API Endpoints
1. **Cancel Job**: Set cancel_requested flag and return immediate response
2. **Pause Job**: Save current state and pause processing
3. **Resume Job**: Continue from saved state
4. **Change Priority**: Update job priority and reorder queue

### 6. Implementation Roadmap

#### Phase 1: Database & Core Logic (Week 1)
- Update database schema
- Add progress tracking to ingestion process
- Implement cancellation checks
- Add change counting logic

#### Phase 2: API Endpoints (Week 1)
- Implement cancel, pause, resume endpoints
- Add priority management
- Update job status reporting

#### Phase 3: UI Enhancements (Week 2)
- Add control buttons to Jobs component
- Create detailed progress modal
- Implement change visualization
- Add job management controls

#### Phase 4: Advanced Features (Week 2)
- Implement pause/resume functionality
- Add job prioritization
- Create job logs export
- Add performance monitoring

### 7. Technical Considerations

#### A. Cancellation Handling
- Check cancel_requested flag every 100 files processed
- Gracefully stop processing and update job status
- Clean up any partial transactions

#### B. Pause/Resume Implementation
- Save current file list position and batch state
- Serialize processing state to database
- Resume from exact position when requested

#### C. Progress Calculation
- For full scans: (files_processed / total_files) * 100
- For incremental: (files_processed / changed_files) * 100
- Update every 500 files or every 30 seconds

#### D. Performance Impact
- Minimal overhead from progress tracking
- Cancellation checks add negligible performance cost
- Database updates batched to reduce I/O

### 8. Security Considerations
- Validate job IDs to prevent unauthorized access
- Implement proper authentication for job control endpoints
- Sanitize file paths to prevent directory traversal
- Rate limit job control operations

### 9. Testing Plan
- Unit tests for cancellation logic
- Integration tests for pause/resume functionality
- API tests for new endpoints
- UI tests for job management controls
- Performance tests to ensure no regression

### 10. Rollout Strategy
1. **Development**: Implement in feature branch with comprehensive testing
2. **Staging**: Deploy to test environment with sample data
3. **Production**: Gradual rollout with monitoring
4. **Monitoring**: Track job completion rates and user feedback